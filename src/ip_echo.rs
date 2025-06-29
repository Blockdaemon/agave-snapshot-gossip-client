use std::net::{IpAddr, SocketAddr, TcpListener};

use anyhow::Result;
use bincode;
use log::{debug, info, warn};
use serde::de;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as TokioTcpListener;

const HEADER_LENGTH: usize = 4;
const DEFAULT_IP_ECHO_SERVER_THREADS: usize = 2;
const MAX_PORT_COUNT_PER_MESSAGE: usize = 4;
const IP_ECHO_SERVER_REQUEST_LENGTH: usize = 16; // 4 tcp ports + 4 udp ports, each u16 (2 bytes)
const IP_ECHO_SERVER_RESPONSE_LENGTH: usize = HEADER_LENGTH + 23; // 16 ipv6 + 1 enum + 2 u16 + 1 some + 3 overhead

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct IpEchoServerMessage {
    tcp_ports: [u16; MAX_PORT_COUNT_PER_MESSAGE],
    udp_ports: [u16; MAX_PORT_COUNT_PER_MESSAGE],
}

// IpEchoServerMessage is used by the client to send its port array to the server
impl IpEchoServerMessage {
    pub fn new(tcp_ports: &[u16], udp_ports: &[u16]) -> Self {
        let mut request = Self::default();
        // Copy and pad tcp_ports
        let tcp_len = tcp_ports.len().min(MAX_PORT_COUNT_PER_MESSAGE);
        request.tcp_ports[..tcp_len].copy_from_slice(&tcp_ports[..tcp_len]);
        // Copy and pad udp_ports
        let udp_len = udp_ports.len().min(MAX_PORT_COUNT_PER_MESSAGE);
        request.udp_ports[..udp_len].copy_from_slice(&udp_ports[..udp_len]);
        request
    }
}

// IpEchoServerResponse is used by the server to send what it thinks is the client IP and its own shred version to the client
// It provides STUN like functionality to get the client IP, and notifies the server what ports the client is listening on
#[derive(Serialize, Deserialize, Debug)]
pub struct IpEchoServerResponse {
    address: IpAddr,
    #[serde(deserialize_with = "default_on_eof")]
    shred_version: Option<u16>,
}

impl IpEchoServerResponse {
    pub fn new(address: IpAddr, shred_version: Option<u16>) -> Self {
        Self {
            address,
            shred_version,
        }
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn shred_version(&self) -> Option<u16> {
        self.shred_version
    }
}

pub fn default_on_eof<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: de::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let value = T::deserialize(deserializer);
    match value {
        Ok(value) => Ok(value),
        Err(err) if err.to_string().contains("EOF") => Ok(T::default()),
        Err(err) => Err(err),
    }
}

async fn handle_ip_echo_connection(
    mut socket: tokio::net::TcpStream,
    shred_version: u16,
) -> Result<()> {
    let peer_addr = socket.peer_addr()?;
    let peer_ip = peer_addr.ip();
    info!("Connect from {}", peer_ip);

    // Read header
    let mut header = [0u8; HEADER_LENGTH];
    if let Err(err) = socket.read_exact(&mut header).await {
        info!("Failed to read header from {}: {:?}", peer_ip, err);
        return Err(err.into());
    }

    // Read request
    let mut request_bytes = vec![0u8; IP_ECHO_SERVER_REQUEST_LENGTH];
    if let Err(err) = socket.read_exact(&mut request_bytes).await {
        info!("Failed to read request from {}: {:?}", peer_ip, err);
        return Err(err.into());
    }

    // Deserialize the request
    let request: IpEchoServerMessage = bincode::deserialize(&request_bytes)?;
    debug!("Message from {}: {:?}", peer_ip, request);

    // Send response
    let response = IpEchoServerResponse::new(peer_ip, Some(shred_version));
    let mut bytes = vec![0u8; IP_ECHO_SERVER_RESPONSE_LENGTH];
    // Write response after header
    bincode::serialize_into(&mut bytes[HEADER_LENGTH..], &response)?;
    if let Err(err) = socket.write_all(&bytes).await {
        info!("Session from {} failed: {:?}", peer_ip, err);
        return Err(err.into());
    }

    // Wait for client to close the connection
    let _ = socket.read(&mut [0u8; 1]).await;
    Ok(())
}

pub fn create_ip_echo_server(ip_echo: Option<TcpListener>, shred_version: u16) {
    let _ip_echo_server = ip_echo.map(|tcp_listener| {
        info!(
            "Starting IP echo server on TCP {}",
            tcp_listener.local_addr().unwrap()
        );

        // Set non-blocking mode once before cloning
        tcp_listener.set_nonblocking(true).unwrap();

        // Spawn multiple tasks in the existing runtime
        for _ in 0..DEFAULT_IP_ECHO_SERVER_THREADS {
            let tcp_listener = TokioTcpListener::from_std(tcp_listener.try_clone().unwrap())
                .expect("Failed to convert std::TcpListener");
            let shred_version = shred_version;
            tokio::spawn(async move {
                loop {
                    match tcp_listener.accept().await {
                        Ok((socket, _)) => {
                            if let Err(err) = handle_ip_echo_connection(socket, shred_version).await
                            {
                                warn!("Error handling connection: {:?}", err);
                            }
                        }
                        Err(err) => warn!("listener accept failed: {:?}", err),
                    }
                }
            });
        }
    });
}

pub async fn ip_echo_client(
    addr: SocketAddr,
    request: IpEchoServerMessage,
) -> Result<(IpAddr, u16)> {
    let mut socket = tokio::net::TcpStream::connect(addr).await?;

    // Send the 4-byte header
    socket.write_all(&[0u8; 4]).await?;

    // Send the port array message
    let mut request_bytes = vec![0u8; IP_ECHO_SERVER_REQUEST_LENGTH];
    bincode::serialize_into(&mut request_bytes, &request).unwrap();
    socket.write_all(&request_bytes).await?;

    // Read the Server Response
    let mut response_bytes = vec![0u8; IP_ECHO_SERVER_RESPONSE_LENGTH];
    socket.read_exact(&mut response_bytes).await?;

    // Verify header bytes
    let header = &response_bytes[..HEADER_LENGTH];
    if header != &[0u8; HEADER_LENGTH] {
        return Err(anyhow::anyhow!("Invalid header bytes: {:?}", header));
    }

    // Deserialize the response, skipping the header
    let response: IpEchoServerResponse =
        bincode::deserialize(&response_bytes[HEADER_LENGTH..]).unwrap();
    let (address, shred_version) = (response.address(), response.shred_version().unwrap());
    Ok((address, shred_version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DEFAULT_GOSSIP_PORT, DEFAULT_RPC_PORT, TESTNET_ENTRYPOINTS};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Helper function to create a test request with default ports
    fn create_test_request() -> IpEchoServerMessage {
        let tcp_ports = [DEFAULT_RPC_PORT, DEFAULT_GOSSIP_PORT];
        let udp_ports = [DEFAULT_GOSSIP_PORT];
        IpEchoServerMessage::new(&tcp_ports, &udp_ports)
    }

    // Helper function to create a test response
    fn create_test_response(shred_version: u16) -> IpEchoServerResponse {
        IpEchoServerResponse::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), Some(shred_version))
    }

    // Helper function to setup a test server that handles a single connection
    async fn setup_test_server<F>(handler: F) -> SocketAddr
    where
        F: FnOnce(
                tokio::net::TcpStream,
            )
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
            + Send
            + 'static,
    {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handler(socket).await.unwrap();
        });

        local_addr
    }

    #[tokio::test]
    async fn test_ip_echo_client() {
        let shred_version = 42;
        let local_addr = setup_test_server(move |socket| {
            Box::pin(handle_ip_echo_connection(socket, shred_version))
        })
        .await;

        let request = create_test_request();
        let (address, version) = ip_echo_client(local_addr, request).await.unwrap();

        assert_eq!(address, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(version, shred_version);
    }

    #[tokio::test]
    async fn test_ip_echo_client_with_entrypoint() {
        let entrypoint = TESTNET_ENTRYPOINTS[0];
        let (host, port) = entrypoint.split_once(':').unwrap();
        let port = port.parse::<u16>().unwrap();

        // Resolve the hostname to an IP address
        let addrs = tokio::net::lookup_host((host, port)).await.unwrap();
        let server_addr = addrs.into_iter().next().unwrap();

        let request = create_test_request();
        match ip_echo_client(server_addr, request).await {
            Ok((address, version)) => {
                println!("Successfully connected to entrypoint {}:", server_addr);
                println!("  - Our IP address as seen by the server: {}", address);
                println!("  - Server's shred version: {}", version);
            }
            Err(err) => {
                println!("Failed to connect to entrypoint {}: {:?}", server_addr, err);
                // Only fail the test if not in CI, since entrypoints might be down in CI
                if std::env::var("CI").is_err() {
                    panic!("Failed to connect to entrypoint {}: {:?}", server_addr, err);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_ip_echo_client_header() {
        let shred_version = 42;
        let local_addr = setup_test_server(move |socket| {
            Box::pin(handle_ip_echo_connection(socket, shred_version))
        })
        .await;

        let request = create_test_request();
        let mut stream = tokio::net::TcpStream::connect(local_addr).await.unwrap();

        let mut bytes = vec![0u8; IP_ECHO_SERVER_REQUEST_LENGTH];
        bincode::serialize_into(&mut bytes, &request).unwrap();
        stream.write_all(&bytes).await.unwrap();

        // Read response
        let mut response_bytes = vec![0u8; IP_ECHO_SERVER_RESPONSE_LENGTH];
        stream.read_exact(&mut response_bytes).await.unwrap();

        // Verify header
        let header = &response_bytes[..HEADER_LENGTH];
        println!("Response header bytes: {:?}", header);
        assert_eq!(header, &[0u8; HEADER_LENGTH], "Header should be all zeros");

        // Deserialize the response, skipping the header
        let response: IpEchoServerResponse =
            bincode::deserialize(&response_bytes[HEADER_LENGTH..]).unwrap();
        assert_eq!(response.address, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(response.shred_version, Some(shred_version));
    }

    #[tokio::test]
    async fn test_ip_echo_client_rejects_invalid_header() {
        let shred_version = 42;
        let local_addr = setup_test_server(move |mut socket| {
            Box::pin(async move {
                let mut header = [0u8; HEADER_LENGTH];
                socket.read_exact(&mut header).await.unwrap();
                let mut request_bytes = vec![0u8; IP_ECHO_SERVER_REQUEST_LENGTH];
                socket.read_exact(&mut request_bytes).await.unwrap();

                let response = create_test_response(shred_version);
                let mut bytes = vec![0u8; IP_ECHO_SERVER_RESPONSE_LENGTH];
                bytes[..HEADER_LENGTH].copy_from_slice(&[1u8; HEADER_LENGTH]);
                bincode::serialize_into(&mut bytes[HEADER_LENGTH..], &response).unwrap();
                socket.write_all(&bytes).await.unwrap();
                Ok(())
            })
        })
        .await;

        let request = create_test_request();
        let result = ip_echo_client(local_addr, request).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid header bytes"));
    }

    #[tokio::test]
    async fn test_create_ip_echo_server() {
        // Start the server
        let server_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let tcp_listener = TokioTcpListener::bind(server_addr).await.unwrap();
        let server_addr = tcp_listener.local_addr().unwrap();
        let shred_version = 12345;
        create_ip_echo_server(Some(tcp_listener.into_std().unwrap()), shred_version);

        // Use our client to connect and get the response
        let (address, version) = ip_echo_client(server_addr, create_test_request())
            .await
            .unwrap();

        // Verify the response
        assert_eq!(address, IpAddr::from([127, 0, 0, 1]));
        assert_eq!(version, shred_version);
    }
}
