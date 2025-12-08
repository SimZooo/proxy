use std::{fs::read_to_string, io, sync::Arc};
use rcgen::{BasicConstraints, Certificate, CertificateParams, CertificateSigningRequest, DnType, IsCa, Issuer, KeyPair, PublicKey, SigningKey};
use tokio::{io::AsyncReadExt, net::TcpStream};
use tokio_rustls::rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::{PemObject, SectionKind}}};

pub async fn read_request(stream: &mut TcpStream) -> io::Result<String> {
    let mut buffer = [0u8; 4096];
    let n = match stream.read(&mut buffer[..]).await {
        Ok(n) => n,
        Err(e) => { eprintln!("Failed to read data from stream: {e}. Error in check_connect"); return Err(e)}
    };
    let request = String::from_utf8_lossy(&buffer[..n]);
    Ok(request.to_string())
}

pub async fn load_ca() -> io::Result<Issuer<'static, KeyPair>> {
    let ca_key_path = "private/ca.key.unencrypted";
    let ca_cert_path = "certs/ca.crt";

    println!("Loading CA key from {}", ca_key_path);
    println!("Loading CA cert from {}", ca_cert_path);

    let ca_key_pem = read_to_string(ca_key_path).map_err(|e| {
        eprintln!("ERROR: Could not read CA certificate file at '{}': {}", ca_cert_path, e);
        io::Error::new(io::ErrorKind::NotFound, 
            format!("Failed to read CA certificate from {}: {}", ca_cert_path, e))
    })?;

    let ca_cert_pem = read_to_string(ca_cert_path).map_err(|e| {
        eprintln!("ERROR: Could not read CA key file at '{}': {}", ca_cert_path, e);
        io::Error::new(io::ErrorKind::NotFound, 
            format!("Failed to read CA key from {}: {}", ca_cert_path, e))
    })?;

    let key_pair = KeyPair::from_pem(&ca_key_pem).map_err(|e| {
        eprintln!("ERROR: Failed to parse CA key PEM: {}", e);
        io::Error::new(io::ErrorKind::InvalidData, 
            format!("Failed to parse CA key: {}", e))
    })?;

    let issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, key_pair).map_err(|e| {
        eprintln!("ERROR: Failed to parse CA certificate: {}", e);
        eprintln!("Certificate content (first 200 chars): {}", 
            &ca_cert_pem.chars().take(200).collect::<String>());
        io::Error::new(io::ErrorKind::InvalidData, 
            format!("Failed to parse CA certificate: {}", e))
    })?;

    println!("Successfully loaded CA certificate");
    Ok(issuer)
}

pub async fn generate_cert(domain: String, issuer: Arc<Issuer<'static, KeyPair>>) -> io::Result<(Certificate, KeyPair)> {
    // Create cert
    let mut params = CertificateParams::new(vec![domain.to_string()]).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, 
            format!("Failed to create certificate params: {}", e))
    })?;
    params.distinguished_name.push(DnType::CommonName, domain);

    let key_pair = KeyPair::generate().unwrap();

    let cert = params.signed_by(&key_pair, &issuer).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, 
            format!("Failed to sign certificate params: {}", e))
    })?;

    Ok((cert, key_pair))
}

pub fn get_domain(request: &String) -> io::Result<String>{
    let lines = request.split("\r\n").collect::<Vec<&str>>();
    let status_line = match lines.first() {
        Some(f) => f,
        None => { return Err(io::Error::new(io::ErrorKind::Other, "Empty request")) }
    };
    let mut split_status_line = status_line.split_whitespace();
    let _ = split_status_line.next();
    let domain = match split_status_line.next() {
        Some(f) => f,
        None => { return Err(io::Error::new(io::ErrorKind::Other, "No target specified in status line")) }
    };
    Ok(domain.to_string())
}

pub async fn create_server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> io::Result<ServerConfig>{
    let cert = CertificateDer::from(cert_der);
    //let key = PrivateKeyDer::from_pem(SectionKind::RsaPrivateKey, key_der).unwrap();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));

    let config = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert], key).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, 
            format!("Failed to build serverconfig: {}", e))
    })?;

    Ok(config)
}