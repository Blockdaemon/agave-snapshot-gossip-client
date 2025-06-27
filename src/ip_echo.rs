// Re-implement solana-net-utils::ip_echo to avoid the dependency on solana-net-utils.
// Massively stripped down to just the IP echo functionality, does not test client ports.
// This means that clients behave as if they used --no-port-check.
use std::net::{IpAddr, SocketAddr, TcpListener};

use anyhow::Result;
use bincode;
use bytes::BytesMut;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use solana_serde::default_on_eof;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as TokioTcpListener;

const HEADER_LENGTH: usize = 4;
const DEFAULT_IP_ECHO_SERVER_THREADS: usize = 2;
const MAX_PORT_COUNT_PER_MESSAGE: usize = 4;
const IP_ECHO_REQUEST_LENGTH: usize = HEADER_LENGTH + 17; // 4 tcp ports + 4 udp ports, each u16 (2 bytes) + \n
const IP_ECHO_RESPONSE_LENGTH: usize = HEADER_LENGTH + 23; // 16 ipv6 + 1 enum + 2 u16 + 1 some + 3 overhead
const CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

// Local macros for bincode operations
macro_rules! bincode_encode_into {
    ($buffer:expr, $value:expr) => {
        bincode::serialize_into($buffer, $value)
    };
}

macro_rules! bincode_decode {
    ($bytes:expr) => {
        bincode::deserialize($bytes)
    };
}

// Local macro for timeout operations
macro_rules! timeout_operation {
    ($operation:expr) => {
        tokio::time::timeout(CLIENT_TIMEOUT, $operation).await??
    };
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct IpEchoClientRequest {
    tcp_ports: [u16; MAX_PORT_COUNT_PER_MESSAGE],
    udp_ports: [u16; MAX_PORT_COUNT_PER_MESSAGE],
}

// IpEchoClientRequest is used by the client to send its port array to the server
impl IpEchoClientRequest {
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

async fn handle_ip_echo_connection(
    mut socket: tokio::net::TcpStream,
    shred_version: u16,
) -> Result<()> {
    let peer_addr = socket.peer_addr()?;
    let peer_ip = peer_addr.ip();
    info!("Connect from {}", peer_ip);

    // Read header and request
    let mut bytes = vec![0u8; IP_ECHO_REQUEST_LENGTH];
    if let Err(err) = socket.read_exact(&mut bytes).await {
        info!("Failed to read request from {}: {:?}", peer_ip, err);
        return Err(err.into());
    }
    debug!("Server: Request {:?} bytes: {:?}", bytes.len(), bytes);

    // Deserialize the request
    let request: IpEchoClientRequest = bincode_decode!(&bytes)?;
    debug!("Message from {}: {:?}", peer_ip, request);

    // Send header and response
    let response = IpEchoServerResponse::new(peer_ip, Some(shred_version));
    let mut bytes = vec![0u8; IP_ECHO_RESPONSE_LENGTH];
    bincode_encode_into!(&mut bytes[HEADER_LENGTH..], &response)?;
    debug!("Server: Response {:?} bytes: {:?}", bytes.len(), bytes);

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
    request: IpEchoClientRequest,
) -> Result<(IpAddr, u16)> {
    let mut socket = timeout_operation!(tokio::net::TcpStream::connect(addr));

    /*
    // This is what solana-net-utils::ip_echo_client.rs does
    // Use same buffer for request and response
    let mut bytes = BytesMut::with_capacity(IP_ECHO_RESPONSE_LENGTH);
    // Start with HEADER_LENGTH null bytes to avoid looking like an HTTP GET/POST request
    bytes.extend_from_slice(&[0u8; HEADER_LENGTH]);
    bytes.extend_from_slice(&bincode_encode!(&request)?);
    // End with '\n' to make this request look HTTP-ish and tickle an error response back
    // from an HTTP server
    bytes.put_u8(b'\n');
    */

    let mut bytes = vec![0u8; IP_ECHO_REQUEST_LENGTH];
    bincode_encode_into!(&mut bytes[HEADER_LENGTH..], &request)?;
    debug!("Client: Request {:?} bytes: {:?}", bytes.len(), bytes);
    bytes[IP_ECHO_REQUEST_LENGTH - 1] = b'\n'; // Set last byte to newline
    socket.write_all(&bytes).await?;
    socket.flush().await?;

    // Read the Server Response
    let mut bytes = BytesMut::with_capacity(IP_ECHO_RESPONSE_LENGTH);
    timeout_operation!(socket.read_buf(&mut bytes));
    socket.shutdown().await?;
    debug!(
        "Client: Response {:?} bytes: {:?}",
        bytes.len(),
        bytes.as_ref()
    );
    // Verify header bytes
    let header = &bytes[..HEADER_LENGTH];
    if header != &[0u8; HEADER_LENGTH] {
        return Err(anyhow::anyhow!("Invalid header bytes: {:?}", header));
    }

    // Deserialize the response, skipping the header
    let response: IpEchoServerResponse = bincode_decode!(&bytes[HEADER_LENGTH..])?;
    let address = response.address();
    let shred_version = response.shred_version().unwrap();
    Ok((address, shred_version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::TESTNET_ENTRYPOINTS;
    use std::net::{IpAddr, SocketAddr};

    // Initialize logger for tests
    fn init_logger() {
        let _ = env_logger::try_init();
    }

    // Helper function to create a test request with no ports
    fn create_test_request() -> IpEchoClientRequest {
        IpEchoClientRequest::default()
    }

    // Helper function to create a test response
    fn create_test_response() -> IpEchoServerResponse {
        IpEchoServerResponse::new(IpAddr::from([127, 0, 0, 1]), Some(42))
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
    // Test the ip_echo_client() api with a local test server
    async fn test_ip_echo_client() {
        init_logger();
        let shred_version = 42;
        let local_addr = setup_test_server(move |socket| {
            Box::pin(handle_ip_echo_connection(socket, shred_version))
        })
        .await;

        let request = create_test_request();
        let (address, version) = ip_echo_client(local_addr, request).await.unwrap();

        assert_eq!(address, IpAddr::from([127, 0, 0, 1]));
        assert_eq!(version, shred_version);
    }

    #[tokio::test]
    // Test with a real remote entrypoint server
    async fn test_ip_echo_client_with_entrypoint() {
        init_logger();
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
    async fn test_ip_echo_client_rejects_invalid_header() {
        init_logger();
        let local_addr = setup_test_server(move |mut socket| {
            Box::pin(async move {
                let mut bytes = vec![0u8; IP_ECHO_REQUEST_LENGTH];
                socket.read_exact(&mut bytes).await.unwrap();
                println!("Server: Request {:?} bytes: {:?}", bytes.len(), bytes);

                let mut bytes = vec![0u8; IP_ECHO_RESPONSE_LENGTH];
                // Set the header to something invalid
                bytes[..HEADER_LENGTH].copy_from_slice(&[1u8; HEADER_LENGTH]);
                // Set response
                let response = create_test_response();
                bincode_encode_into!(&mut bytes[HEADER_LENGTH..], &response).unwrap();
                println!("Server: Response {:?} bytes: {:?}", bytes.len(), bytes);
                socket.write_all(&bytes).await.unwrap();
                Ok(())
            })
        })
        .await;

        let request = create_test_request();
        let result = ip_echo_client(local_addr, request).await;
        println!("Result: {:?}", result);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid header bytes"));
    }

    #[tokio::test]
    async fn test_create_ip_echo_server() {
        init_logger();
        // Start the server
        let server_ip = IpAddr::from([127, 0, 0, 1]);
        let server_addr = SocketAddr::from((server_ip, 0));
        let tcp_listener = TokioTcpListener::bind(server_addr).await.unwrap();
        let listener_addr = tcp_listener.local_addr().unwrap();
        let shred_version = 12345;
        create_ip_echo_server(Some(tcp_listener.into_std().unwrap()), shred_version);

        // Use our client to connect and get the response
        let (address, version) = ip_echo_client(listener_addr, create_test_request())
            .await
            .unwrap();

        // Verify the response
        assert_eq!(address, server_ip);
        assert_eq!(version, shred_version);
    }
}
