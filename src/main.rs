#![warn(rust_2018_idioms)]

use clap::Clap;
use tokio::io::{AsyncReadExt, ErrorKind, Interest};
use tokio::net::TcpStream;
use tokio::runtime::Builder;

use std::error::Error;
use std::net::SocketAddr;

#[derive(Clap)]
#[clap(version = "0.1")]
struct Opts {
    server_addr: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opts = Opts::parse();
    println!("Server addr: {}", opts.server_addr);

    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(logic_loop(opts.server_addr))
}

async fn logic_loop(server_addr: String) -> Result<(), Box<dyn Error>> {
    let addr = server_addr.parse::<SocketAddr>()?;

    let mut stream = TcpStream::connect(addr).await?;

    const BUF_SIZE: usize = 4096;
    let mut buf: [u8; BUF_SIZE] = [0; BUF_SIZE];

    loop {
        let ready = stream.ready(Interest::READABLE).await?;

        if ready.is_readable() {
            let mut bytes_read: usize = 0;
            match stream.read(&mut buf).await {
                Ok(n) => bytes_read = n,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }

            if bytes_read == 0 {
                break;
            }

            
        }
    }

    Ok(())
}
