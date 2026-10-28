//! Shutting down: the API keeps answering while bridges are sent elsewhere, so a deploy fails no requests.

mod common;

use std::time::Duration;

use common::TestServer;
use futures_util::{SinkExt, StreamExt};
use opentunnel::protocol::bridge::{
    ClientInfo, ClientMessage, ServerMessage, Transport, WEBSOCKET_SUBPROTOCOL,
};
use opentunnel::{Client, ClientOptions, Storage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Sends one keep-alive request and reads its whole response.
async fn request(stream: &mut TcpStream, path: &str) -> String {
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {}\r\n\r\n", common::DOMAIN).as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        response.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&response);
        if read == 0 || text.ends_with("}") {
            return text.into_owned();
        }
    }
}

async fn closed(stream: &mut TcpStream) -> bool {
    let mut buffer = [0u8; 64];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await,
        Ok(Ok(0) | Err(_))
    )
}

#[tokio::test]
async fn keeps_serving_while_draining() {
    let dir = tempfile::tempdir().unwrap();
    let Some(server) = TestServer::start(dir.path(), &[]).await else {
        return;
    };
    let client = Client::new(ClientOptions {
        api: Some(server.api.parse().unwrap()),
        owner_token: Some(common::OWNER_TOKEN.into()),
        storage: Some(Storage::at(dir.path().join("client"))),
        ..Default::default()
    });
    let identity = client.create("default", |_| {}).await.unwrap();

    let mut idle = TcpStream::connect(server.http).await.unwrap();
    assert!(
        request(&mut idle, "/health")
            .await
            .starts_with("HTTP/1.1 200")
    );

    server.service().drain().await;
    server.server.app.shutdown.drain();

    // A connection open before the drain closes once idle, so its client opens a new one elsewhere.
    assert!(closed(&mut idle).await);

    // New connections are still served, one request each.
    let mut late = TcpStream::connect(server.http).await.unwrap();
    let response = request(&mut late, "/health").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.to_ascii_lowercase().contains("connection: close"));
    assert!(closed(&mut late).await);
    let info = client
        .api()
        .get(&identity.token, &identity.id)
        .await
        .unwrap();
    assert_eq!(info.id, identity.id);

    // A bridge that arrives now is told to reconnect elsewhere instead of attaching here.
    let url = format!(
        "{}/api/tunnel/{}/connect",
        server.api.replace("http://", "ws://"),
        identity.id
    );
    let mut upgrade = url.into_client_request().unwrap();
    upgrade.headers_mut().insert(
        "sec-websocket-protocol",
        WEBSOCKET_SUBPROTOCOL.parse().unwrap(),
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(upgrade).await.unwrap();
    let attach = ClientMessage::Attach {
        token: identity.token.clone(),
        transport: Transport::Ws,
        routes: vec!["@".into()],
        client: ClientInfo {
            version: "test".into(),
            max_conns: 10,
        },
    };
    let _ = socket
        .send(Message::text(serde_json::to_string(&attach).unwrap()))
        .await;
    let mut drained = false;
    let mut close = None;
    while let Ok(Some(Ok(message))) =
        tokio::time::timeout(Duration::from_secs(5), socket.next()).await
    {
        match message {
            Message::Text(text) => match ServerMessage::decode(&text).unwrap() {
                Some(ServerMessage::Drain { .. }) => drained = true,
                Some(ServerMessage::Attached { .. }) => panic!("attached while draining"),
                _ => {}
            },
            Message::Close(frame) => {
                close = frame.map(|frame| u16::from(frame.code));
                break;
            }
            _ => {}
        }
    }
    assert!(drained);
    assert_eq!(close, Some(1012));
    assert_eq!(server.service().bridge_count(), 0);

    assert!(
        server
            .server
            .app
            .shutdown
            .close(Duration::from_secs(5))
            .await
    );
    server.stop().await;
}
