#![warn(rust_2018_idioms)]

use clap::Clap;
use tokio::io::{AsyncReadExt, ErrorKind, Interest};
use tokio::net::TcpStream;
use tokio::runtime::Builder;

use std::error::Error;
use std::net::SocketAddr;

use ffmpeg_sys_next::{self, AVCodecContext, AVCodecID, AVCodecParserContext, AVFrame, AVPacket};
use std::fmt::Formatter;

use libc;

use sdl2::event::Event;
use sdl2::keyboard::Keycode;
use sdl2::pixels::PixelFormatEnum;
use sdl2::rect::Rect;

#[derive(Clap)]
#[clap(version = "0.1")]
struct Opts {
    server_addr: String,
}

struct RaspividDecoder {
    context: *mut AVCodecContext,
    frame: *mut AVFrame,
    packet: *mut AVPacket,
    parser: *mut AVCodecParserContext,
}

#[derive(Debug)]
enum RaspividError {
    CodecNotFound,
    OpenError(i32),
    ParserInitializationFailed,
    FrameAllocFailed,
    PacketAllocFailed,
    DecodeError(i32),
    AVCodecSendPacketError(i32),
    AVCodecReceiveFrameError(i32),
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
            let mut context = ffmpeg_sys_next::avcodec_alloc_context3(codec);
            let result = ffmpeg_sys_next::avcodec_open2(context, codec, std::ptr::null_mut());
            if result < 0 {
                ffmpeg_sys_next::avcodec_free_context(&mut context);
                return Err(RaspividError::OpenError(result));
            }

            let mut frame = ffmpeg_sys_next::av_frame_alloc();
            if frame.is_null() {
                ffmpeg_sys_next::avcodec_free_context(&mut context);
                return Err(RaspividError::FrameAllocFailed);
            }

            let parser =
                ffmpeg_sys_next::av_parser_init(AVCodecID::AV_CODEC_ID_H264 as libc::c_int);
            if parser.is_null() {
                ffmpeg_sys_next::avcodec_free_context(&mut context);
                ffmpeg_sys_next::av_frame_free(&mut frame);
                return Err(RaspividError::ParserInitializationFailed);
            }

            let packet = ffmpeg_sys_next::av_packet_alloc();
            if packet.is_null() {
                ffmpeg_sys_next::avcodec_free_context(&mut context);
                ffmpeg_sys_next::av_frame_free(&mut frame);
                ffmpeg_sys_next::av_parser_close(parser);
                return Err(RaspividError::PacketAllocFailed);
            }

            Ok(RaspividDecoder {
                context,
                frame,
                packet,
                parser,
            })
        }
    }

    pub fn decode_data<F: FnMut(&[u8], &[u8], &[u8], usize, usize, usize, usize, usize)>(
        &self,
        data: &[u8],
        mut decode_handler: F,
    ) -> Result<(), RaspividError> {
        let mut data_len = data.len();
        let mut offset: usize = 0;
        while data_len > 0 {
            let slice = &data[offset..];
            let bytes_parsed = unsafe {
                ffmpeg_sys_next::av_parser_parse2(
                    self.parser,
                    self.context,
                    &mut self.packet.as_mut().unwrap().data,
                    &mut self.packet.as_mut().unwrap().size,
                    slice.as_ptr(),
                    slice.len() as libc::c_int,
                    ffmpeg_sys_next::AV_NOPTS_VALUE,
                    ffmpeg_sys_next::AV_NOPTS_VALUE,
                    0,
                )
            };

            if bytes_parsed < 0 {
                return Err(RaspividError::DecodeError(bytes_parsed));
            }

            offset += bytes_parsed as usize;
            data_len -= bytes_parsed as usize;

            if unsafe { self.packet.as_ref().unwrap().size > 0 } {
                let ret =
                    unsafe { ffmpeg_sys_next::avcodec_send_packet(self.context, self.packet) };
                if ret < 0 {
                    return Err(RaspividError::AVCodecSendPacketError(ret));
                }

                loop {
                    let ret =
                        unsafe { ffmpeg_sys_next::avcodec_receive_frame(self.context, self.frame) };

                    if ret == -ffmpeg_sys_next::EAGAIN || ret == ffmpeg_sys_next::AVERROR_EOF {
                        continue;
                    } else if ret < 0 {
                        return Err(RaspividError::AVCodecReceiveFrameError(ret));
                    }

                    let y_line_size = unsafe { self.frame.as_ref().unwrap().linesize[0] as usize };
                    let u_line_size = unsafe { self.frame.as_ref().unwrap().linesize[1] as usize };
                    let v_line_size = unsafe { self.frame.as_ref().unwrap().linesize[2] as usize };
                    let width = unsafe { self.frame.as_ref().unwrap().width as usize };
                    let height = unsafe { self.frame.as_ref().unwrap().height as usize };

                    let y_data = unsafe {
                        std::slice::from_raw_parts(
                            self.frame.as_ref().unwrap().data[0],
                            y_line_size * height,
                        )
                    };

                    let u_data = unsafe {
                        std::slice::from_raw_parts(
                            self.frame.as_ref().unwrap().data[1],
                            u_line_size * height / 2,
                        )
                    };

                    let v_data = unsafe {
                        std::slice::from_raw_parts(
                            self.frame.as_ref().unwrap().data[2],
                            v_line_size * height / 2,
                        )
                    };

                    decode_handler(
                        y_data,
                        u_data,
                        v_data,
                        y_line_size,
                        u_line_size,
                        v_line_size,
                        width,
                        height,
                    );

                    if ret == 0 {
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

impl Drop for RaspividDecoder {
    fn drop(&mut self) {
        if !self.packet.is_null() {
            unsafe {
                ffmpeg_sys_next::av_packet_free(&mut self.packet);
            }
        }

        if !self.parser.is_null() {
            unsafe {
                ffmpeg_sys_next::av_parser_close(self.parser);
            }
        }

        if !self.frame.is_null() {
            unsafe {
                ffmpeg_sys_next::av_frame_free(&mut self.frame);
            }
        }

        if !self.context.is_null() {
            unsafe {
                ffmpeg_sys_next::avcodec_free_context(&mut self.context);
            }
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
    let sdl_context = sdl2::init().unwrap();
    let video_subsystem = sdl_context.video().unwrap();
    let window = video_subsystem
        .window("Ruspivid Decode", 800, 600)
        .position_centered()
        .resizable()
        .build()
        .unwrap();
    let mut canvas = window.into_canvas().build().unwrap();
    let texture_creator = canvas.texture_creator();
    let mut texture = texture_creator
        .create_texture_streaming(PixelFormatEnum::IYUV, 800 as u32, 600 as u32)
        .unwrap();
    canvas.clear();
    canvas.present();

    let mut event_pump = sdl_context.event_pump().unwrap();

    let decoder = RaspividDecoder::new()?;

    let addr = server_addr.parse::<SocketAddr>()?;

    let mut stream = TcpStream::connect(addr).await?;

    const BUF_SIZE: usize = 4096;
    let mut buf: [u8; BUF_SIZE] = [0; BUF_SIZE];

    'main_loop: loop {
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

            decoder.decode_data(
                &buf,
                |y_data, u_data, v_data, y_line_size, u_line_size, v_line_size, width, height| {
                    let (window_width, window_height) = canvas.window().size();
                    if (width != window_width as usize) || (height != window_height as usize) {
                        canvas
                            .window_mut()
                            .set_size(width as u32, height as u32)
                            .unwrap();
                        canvas.clear();

                        texture = texture_creator
                            .create_texture_streaming(
                                PixelFormatEnum::IYUV,
                                width as u32,
                                height as u32,
                            )
                            .unwrap();
                    }

                    texture
                        .update_yuv(
                            Rect::new(0, 0, width as u32, height as u32),
                            y_data,
                            y_line_size,
                            u_data,
                            u_line_size,
                            v_data,
                            v_line_size,
                        )
                        .unwrap();

                    canvas.copy(&texture, None, None).unwrap();
                    canvas.present();
                },
            )?;
        }

        for event in event_pump.poll_iter() {
            match event {
                Event::Quit { .. }
                | Event::KeyDown {
                    keycode: Some(Keycode::Escape),
                    ..
                } => break 'main_loop,
                _ => {}
            }
        }
    }

    Ok(())
}
