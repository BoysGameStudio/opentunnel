//! Socket hygiene: every public, internal and outbound connection must end even when its peer vanishes
//! without a FIN or a reset (NAT timeouts, mobile clients, a crashed machine) or only half-closes.
//!
//! - TCP keepalive on every socket, so the kernel notices a dead peer;
//! - an idle timeout on carried connections (nothing in either direction), and a shorter one once either
//!   direction has ended, so a half-closed connection whose other side never ends is closed too;
//! - the open file limit raised to the hard limit, and accept loops that back off when it is reached.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{info, warn};

/// First keepalive probe after this much silence, then every `KEEPALIVE_INTERVAL`; a peer that answers none of
/// `KEEPALIVE_RETRIES` probes is gone (about two minutes in all).
const KEEPALIVE_TIME: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_RETRIES: u32 = 4;
const COPY_BUFFER: usize = 32 * 1024;

/// Turns on TCP keepalive.
pub fn keepalive(stream: &TcpStream) {
    let params = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_TIME)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&params);
}

/// Connections the kernel queues before they are accepted. Tokio's default of 1024 overflowed in reconnect
/// storms (the kernel then drops handshakes, which the proxy reports as failed connections); the kernel caps
/// this at `net.core.somaxconn`.
const LISTEN_BACKLOG: u32 = 16 * 1024;

/// Binds a listener with a backlog deep enough for reconnect storms.
pub fn listen(address: std::net::SocketAddr) -> io::Result<tokio::net::TcpListener> {
    let socket = if address.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    // As std's and Tokio's own bind do, so a restarted server can bind while old connections linger.
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(address)?;
    socket.listen(LISTEN_BACKLOG)
}

/// TCP keepalive, and no Nagle delay: the server forwards whatever it has at once (control messages, data
/// frames, TLS records), and Nagle's wait for an ACK held small writes back for the peer's delayed ACK (40 ms).
pub fn tune(stream: &TcpStream) {
    keepalive(stream);
    let _ = stream.set_nodelay(true);
}

/// How long a carried connection may go without traffic.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// Nothing in either direction: long enough for idle but valid connections (WebSockets, keep-alive).
    pub idle: Duration,
    /// Once either direction has ended, the other must move within this long.
    pub half_close: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(15 * 60),
            half_close: Duration::from_secs(60),
        }
    }
}

/// When a carried connection last moved, shared by its two directions.
pub struct Activity {
    start: Instant,
    /// Milliseconds after `start`.
    last: AtomicU64,
    half_closed: AtomicBool,
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            last: AtomicU64::new(0),
            half_closed: AtomicBool::new(false),
        }
    }
}

impl Activity {
    pub fn touch(&self) {
        let elapsed = self.start.elapsed().as_millis() as u64;
        self.last.fetch_max(elapsed, Ordering::Relaxed);
    }

    /// One direction ended; the other now gets `Timeouts::half_close`.
    pub fn half_close(&self) {
        self.touch();
        self.half_closed.store(true, Ordering::Relaxed);
    }

    /// Resolves once the connection has been quiet for longer than allowed.
    pub async fn expired(&self, timeouts: Timeouts) {
        loop {
            let limit = if self.half_closed.load(Ordering::Relaxed) {
                timeouts.half_close
            } else {
                timeouts.idle
            };
            let deadline =
                self.start + Duration::from_millis(self.last.load(Ordering::Relaxed)) + limit;
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            // Wake at least every `half_close`, so a half-close shortens the wait.
            tokio::time::sleep_until(deadline.min(now + timeouts.half_close)).await;
        }
    }
}

/// Copies both directions until both have ended. A FIN is passed on as a half-close; the connection ends with
/// an error on a failure in either direction or when it stays quiet for longer than `timeouts` allow. The
/// caller then resets both sockets.
pub async fn splice<A, B>(a: &mut A, b: &mut B, timeouts: Timeouts) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Activity::default();
    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);
    let forward = copy(&mut a_read, &mut b_write, &activity);
    let backward = copy(&mut b_read, &mut a_write, &activity);
    tokio::pin!(forward, backward);
    let (mut forward_done, mut backward_done) = (false, false);
    while !(forward_done && backward_done) {
        tokio::select! {
            result = &mut forward, if !forward_done => {
                result?;
                forward_done = true;
            }
            result = &mut backward, if !backward_done => {
                result?;
                backward_done = true;
            }
            () = activity.expired(timeouts) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connection idle"));
            }
        }
    }
    Ok(())
}

async fn copy<R, W>(read: &mut R, write: &mut W, activity: &Activity) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; COPY_BUFFER];
    loop {
        let read = read.read(&mut buffer).await?;
        if read == 0 {
            activity.half_close();
            return write.shutdown().await;
        }
        write.write_all(&buffer[..read]).await?;
        activity.touch();
    }
}

/// Open file descriptors of this process (Linux), for `/api/admin/stats`.
pub fn open_fds() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd").ok().map(Iterator::count)
}

/// Raises the open file soft limit to the hard limit: every connection holds at least one descriptor.
pub fn raise_fd_limit() {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit and setrlimit only read and write the struct passed to them.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            warn!(error = %io::Error::last_os_error(), "could not read the open file limit");
            return;
        }
        let soft = limit.rlim_cur;
        if soft < limit.rlim_max {
            limit.rlim_cur = limit.rlim_max;
            // SAFETY: as above.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
                warn!(soft, hard = limit.rlim_max, error = %io::Error::last_os_error(), "could not raise the open file limit");
                return;
            }
        }
        info!(
            previous = soft,
            soft = limit.rlim_cur,
            hard = limit.rlim_max,
            "open file limit"
        );
    }
}

/// Logs a failed accept and waits before the next one. Running out of descriptors (`EMFILE`, `ENFILE`) waits
/// longer, so the loop does not spin while connections close, and is logged at most every ten seconds.
pub struct AcceptErrors {
    what: &'static str,
    logged_at: Option<Instant>,
    suppressed: u64,
}

impl AcceptErrors {
    pub fn new(what: &'static str) -> Self {
        Self {
            what,
            logged_at: None,
            suppressed: 0,
        }
    }

    pub async fn failed(&mut self, error: io::Error) {
        let exhausted = matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE));
        crate::metrics::accept_error(&error);
        if self
            .logged_at
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(10))
        {
            let error_class = if exhausted { "emfile" } else { "other" };
            warn!(%error, error_class, suppressed = self.suppressed, "{}", self.what);
            self.logged_at = Some(Instant::now());
            self.suppressed = 0;
        } else {
            self.suppressed += 1;
        }
        let pause = if exhausted {
            Duration::from_millis(500)
        } else {
            Duration::from_millis(50)
        };
        tokio::time::sleep(pause).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    const SHORT: Timeouts = Timeouts {
        idle: Duration::from_millis(400),
        half_close: Duration::from_millis(200),
    };

    #[tokio::test]
    async fn splice_carries_data_and_half_closes() {
        let (mut visitor, mut near) = pair().await;
        let (mut far, mut target) = pair().await;
        let splicing = tokio::spawn(async move { splice(&mut near, &mut far, SHORT).await });
        visitor.write_all(b"ping").await.unwrap();
        visitor.shutdown().await.unwrap();
        let mut received = Vec::new();
        target.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"ping");
        target.write_all(b"pong").await.unwrap();
        target.shutdown().await.unwrap();
        let mut received = Vec::new();
        visitor.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"pong");
        splicing.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn splice_ends_idle_connections() {
        let (_visitor, mut near) = pair().await;
        let (mut far, _target) = pair().await;
        let started = Instant::now();
        let result = splice(&mut near, &mut far, SHORT).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= SHORT.idle);
    }

    #[tokio::test]
    async fn splice_ends_half_closed_connections() {
        let (visitor, mut near) = pair().await;
        let (mut far, _target) = pair().await;
        // The visitor goes away; the target keeps its side open and says nothing.
        drop(visitor);
        let started = Instant::now();
        let result = splice(&mut near, &mut far, SHORT).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < SHORT.idle);
    }

    #[tokio::test]
    async fn activity_postpones_the_timeout() {
        let activity = Activity::default();
        let started = Instant::now();
        let touching = async {
            for _ in 0..4 {
                tokio::time::sleep(Duration::from_millis(150)).await;
                activity.touch();
            }
        };
        tokio::join!(touching, activity.expired(SHORT));
        assert!(started.elapsed() >= Duration::from_millis(600 + 400));
    }
}
