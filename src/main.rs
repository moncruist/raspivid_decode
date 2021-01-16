#![warn(rust_2018_idioms)]

use clap::Clap;
use tokio::io::{AsyncReadExt, ErrorKind, Interest};
use tokio::net::TcpStream;
use tokio::runtime::Builder;

use std::error::Error;
use std::net::SocketAddr;

use ffmpeg_sys_next::{self, AVCodecContext, AVCodecID, AVFrame, AVCodecParserContext};
use std::fmt::Formatter;

#[derive(Clap)]
#[clap(version = "0.1")]
struct Opts {
    server_addr: String,
}

struct RaspividDecoder {
    av_ctx: *mut AVCodecContext,
}

#[derive(Debug)]
enum RaspividError {
    CodecNotFound,
    OpenError(i32),
}

impl std::error::Error for RaspividError {}

impl std::fmt::Display for RaspividError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl RaspividDecoder {
    pub fn new() -> Result<RaspividDecoder, RaspividError> {
        unsafe {
            let codec = ffmpeg_sys_next::avcodec_find_decoder(AVCodecID::AV_CODEC_ID_H264);
            if codec.is_null() {
                return Err(RaspividError::CodecNotFound);
            }
            let ctx = ffmpeg_sys_next::avcodec_alloc_context3(codec);
            let result = ffmpeg_sys_next::avcodec_open2(ctx, codec, std::ptr::null_mut());
            if result < 0 {
                return Err(RaspividError::OpenError(result));
            }
            Ok(RaspividDecoder { av_ctx: ctx })
        }
    }
}

impl Drop for RaspividDecoder {
    fn drop(&mut self) {
        if !self.av_ctx.is_null() {
            unsafe {
                ffmpeg_sys_next::avcodec_free_context(&mut self.av_ctx);
            }
        }
    }
}

struct RaspividFrame {
    frame: *mut AVFrame,
}

impl RaspividFrame {
    pub fn new() -> RaspividFrame {
        let frame = unsafe { ffmpeg_sys_next::av_frame_alloc() };
        RaspividFrame { frame }
    }
}

impl Drop for RaspividFrame {
    fn drop(&mut self) {
        if !self.frame.is_null() {
            unsafe { ffmpeg_sys_next::av_frame_free(&mut self.frame); }
        }
    }
}

struct RaspividParser {
    parser: *mut AVCodecParserContext,
}

impl RaspividParser {
    pub fn new() -> RaspividParser {
        let parser = unsafe { ffmpeg_sys_next::av_parser_init() };
        RaspividParser { parser }
    }
}

impl Drop for RaspividParser {
    fn drop(&mut self) {
        if !self.parser.is_null() {
            unsafe { ffmpeg_sys_next::av_parser_close(self.parser); }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opts = Opts::parse();
    println!("Server addr: {}", opts.server_addr);

    unsafe {
        ffmpeg_sys_next::av_register_all();
    }

    Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(logic_loop(opts.server_addr))
}

async fn logic_loop(server_addr: String) -> Result<(), Box<dyn Error>> {
    let decoder = RaspividDecoder::new()?;
    let frame = RaspividFrame::new();

    let addr = server_addr.parse::<SocketAddr>()?;

    let mut stream = TcpStream::connect(addr).await?;

    const BUF_SIZE: usize = 4096;
    let mut buf: [u8; BUF_SIZE] = [0; BUF_SIZE];

    loop {
        let ready = stream.ready(Interest::READABLE).await?;

        if ready.is_readable() {
            let bytes_read: usize;
            match stream.read(&mut buf).await {
                Ok(n) => bytes_read = n,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }

            if bytes_read == 0 {
                println!("Transmission end");
                break;
            }

            println!("Read bytes: {}", bytes_read);
        }
    }

    Ok(())
}
