use std::{error::Error, io, net::SocketAddr, process::exit, sync::Arc};

use hyper::{HeaderMap, header::{HeaderName, HeaderValue}};
use rcgen::{Issuer, KeyPair};
use reqwest::Client;
use tokio::{io::{AsyncReadExt, AsyncWriteExt, split}, net::{TcpListener, TcpStream}, sync::mpsc::Sender};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::network::{create_server_config, generate_cert, get_domain, load_ca, read_request};
mod network;

pub struct FlowRequest {
    pub raw: String,
}

pub struct FlowResponse {
    pub raw: String,
}

#[derive(Debug)]
pub struct Flow {
    pub id: String,
    // TODO: implement requests and responses
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    let listener = match TcpListener::bind("127.0.0.1:3009").await {
        Ok(listener) => listener,
        Err(e) => { eprintln!("Failed to bind listener {e}"); exit(1)}
    };

    let issuer = Arc::new(load_ca().await.unwrap());
    let mut flows: Vec<Flow> = vec![];
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Flow>(100);

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let issuer = issuer.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let body = handle_client_connection(&mut stream, issuer, tx).await?;
                    forward_to_client(body).await;
                    Ok(()) as io::Result<()>
                });
            }
        }
    });

    while let Some(flow) = rx.recv().await {
        println!("Received flow: {:?}", flow);
        flows.push(flow);
        println!("Total flows: {}", flows.len());
    }

    Ok(())
}

async fn handle_client_connection(stream: &mut TcpStream, issuer: Arc<Issuer<'static, KeyPair>>, tx: Sender<Flow>) -> io::Result<String> {
    let req = read_request(stream).await?;
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

    let cert_der = cert.der();
    let key_der = key.serialize_der();
    let server_config = create_server_config(cert_der.to_vec(), key_der).await?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let mut tls_stream = tls_acceptor.accept(stream).await?;
    let _ = tx.send(Flow {
        id: Uuid::new_v4().to_string()
    }).await;

    loop {
        let mut buf = vec![0u8; 4096];
        let n = tls_stream.read(&mut buf[..]).await?;
        if n == 0 {
            break;
        }
        let out = String::from_utf8_lossy(&buf[..n]);
        return Ok(out.to_string())
    }

    Ok("".to_string())
}

async fn forward_to_client(raw: String) {
    let client = Client::new();
    let raw_owned = raw.clone();

    if let Some((headers_str, body)) = raw_owned.split_once("\r\n\r\n") {
        let mut headers = HeaderMap::new();

        let headers_split: Vec<String> = headers_str
            .lines()
            .skip(1)
            .map(|line| line.to_string())
            .collect();

        let request_line = headers_str.lines().next().unwrap();
        let (method, path, _version) =
            match request_line.split_whitespace().collect::<Vec<&str>>()[..] {
                [m, p, v] => (m, p, v),
                _ => {
                    eprintln!("Invalid request line: {}", request_line);
                    return;
                }
            };

        let mut host = None;
        for header in headers_split {
            if let Some((key, value)) = header.split_once(":") {
                if key.to_lowercase() == "host" {
                    host = Some(value.trim().to_string());
                }

                let hname = HeaderName::from_bytes(key.trim().as_bytes()).unwrap();
                let hvalue = HeaderValue::from_str(value.trim()).unwrap();
                headers.insert(hname, hvalue);
            }
        }

        headers.remove("accept-encoding");

        let url = match host {
            Some(host) => {
                format!("https://{host}{path}")
            }
            None => path.to_string(),
        };

        println!("Sending to {:?} {}", method, url);

        let mut req = match method {
            "GET" => client.get(url.clone()),
            "POST" => client.post(url.clone()),
            _ => return,
        };

        req = req.headers(headers);

        if method == "POST" {
            req = req.body(body.to_string());
        }

        let res = req.send().await;

        if let Ok(res) = res {
            println!("{:?}", res.text().await);
        }
    }
}