//! Starting up: a slow database connection still gets through, and an unreachable database fails startup after
//! STARTUP_DB_TIMEOUT_MS, so the platform restarts the machine.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use opentunnel_server::clock::Clock;
use opentunnel_server::server::Server;
use opentunnel_server::store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn an_unreachable_database_fails_startup_after_the_timeout() {
    opentunnel_server::install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let config = common::config(
        dir.path(),
        &format!("mysql://root@127.0.0.1:{port}/opentunnel"),
        &["--startup-db-timeout-ms=1000"],
    );

    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        Server::build(config, Clock::system()),
    )
    .await
    .expect("startup gives up instead of waiting forever");
    let Err(error) = result else {
        panic!("startup succeeded without a database");
    };
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert!(
        format!("{error:#}").contains("the database was unreachable"),
        "{error:#}"
    );
}

/// Copies `from` to `to`, delivering each chunk `delay` after it was read, in order.
async fn delayed(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    delay: Duration,
) {
    let (sender, mut receiver) =
        tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((at, bytes)) = receiver.recv().await {
            tokio::time::sleep_until(at).await;
            if to.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = to.shutdown().await;
    });
    let mut buffer = vec![0u8; 16 * 1024];
    while let Ok(read) = from.read(&mut buffer).await {
        if read == 0
            || sender
                .send((tokio::time::Instant::now() + delay, buffer[..read].to_vec()))
                .is_err()
        {
            return;
        }
    }
}

/// A TCP proxy to `target` that delays every chunk by `delay` each way, like a far-away database.
async fn slow_proxy(target: String, delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((visitor, _)) = listener.accept().await {
            let target = target.clone();
            tokio::spawn(async move {
                let Ok(upstream) = TcpStream::connect(&target).await else {
                    return;
                };
                let (visitor_read, visitor_write) = visitor.into_split();
                let (upstream_read, upstream_write) = upstream.into_split();
                tokio::join!(
                    delayed(visitor_read, upstream_write, delay),
                    delayed(upstream_read, visitor_write, delay),
                );
            });
        }
    });
    address
}

#[tokio::test]
async fn startup_gets_through_a_slow_database_connection() {
    opentunnel_server::install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let Some(url) = common::database_url(dir.path()).await else {
        return;
    };
    // Migrated directly, so the slow startup only has to see the schema is current.
    Store::open(&url).await.unwrap().close().await;
    let mut parsed = url::Url::parse(&url).unwrap();
    let target = format!(
        "{}:{}",
        parsed.host_str().unwrap(),
        parsed.port().unwrap_or(3306)
    );
    let proxy = slow_proxy(target, Duration::from_millis(500)).await;
    parsed.set_ip_host(proxy.ip()).unwrap();
    parsed.set_port(Some(proxy.port())).unwrap();
    let slow = parsed.to_string();

    // The old pool settings: every connection is cut off by the 3 s acquire timeout.
    let options = opentunnel_server::store::connect_options(&slow).unwrap();
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect_lazy_with(options);
    let started = Instant::now();
    let Err(error) = pool.acquire().await else {
        panic!("a 3 s acquire got a connection");
    };
    assert!(matches!(error, sqlx::Error::PoolTimedOut), "{error}");
    eprintln!("3 s acquire: {error} after {:?}", started.elapsed());
    pool.close().await;

    let config = common::config(dir.path(), &slow, &["--startup-db-timeout-ms=60000"]);
    let started = Instant::now();
    let server = Server::build(config, Clock::system())
        .await
        .expect("startup gets through a slow connection");
    eprintln!("startup took {:?}", started.elapsed());
    drop(server);
}
