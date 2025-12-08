use std::{error::Error, io, net::SocketAddr, process::exit, sync::Arc};

use tls_parser::{TlsExtension, TlsMessage, TlsMessageHandshake, parse_tls_extension, parse_tls_plaintext};
use tokio::{io::{AsyncReadExt, AsyncWriteExt, split}, net::{TcpListener, TcpStream}};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls::{ClientConfig, ConfigBuilder, RootCertStore, ServerConfig, pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject}}};

use crate::network::{create_server_config, generate_cert, get_domain, load_ca, read_request};
mod network;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let listener = match TcpListener::bind("127.0.0.1:3009").await {
        Ok(listener) => listener,
        Err(e) => { eprintln!("Failed to bind listener {e}"); exit(1)}
    };

    let issuer = Arc::new(load_ca().await.unwrap());

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let issuer = issuer.clone();
            println!("==== NEW CONNECTION ====");
            tokio::spawn(async move {
                let req = read_request(&mut stream).await?;
                if !req.starts_with("CONNECT") {
                    return Err(io::Error::new(io::ErrorKind::Other, "Expected CONNECT"));
                }

                // Generate cert and key-pair for domain
                let domain_line = get_domain(&req)?;
                let domain_line = domain_line.split(":").collect::<Vec<&str>>();
                let domain = domain_line[0];
                let port = domain_line[1];
                let (cert, key) = generate_cert(domain.to_string(), issuer).await?;
                stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                println!("Established connection to host requesting {}:{}", domain, port);

                let cert_der = cert.der();
                let key_der = key.serialize_der();
                let server_config = create_server_config(cert_der.to_vec(), key_der).await?;
                let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
                println!("Starting TLS connection");

                let mut tls_stream = tls_acceptor.accept(stream).await?;
                println!("TLS connection accepted from client");
                loop {
                    let mut buf = vec![0u8; 4096];
                    let n = tls_stream.read(&mut buf[..]).await?;
                    if n == 0 {
                        break;
                    }
                    let out = String::from_utf8_lossy(&buf[..n]);
                    println!("{}", out);
                }
                println!("==== CONNECTION CLOSED ====");
                Ok(()) as io::Result<()>
            });
        }
    }
}
