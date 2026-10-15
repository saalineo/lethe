use std::io::{self, Read, Write};
use zeroize::Zeroize;

use super::loader::LoadedSymbols;

pub struct TransportHandle {
    pub syms: LoadedSymbols,
    pub node_handle: i32,
}

impl TransportHandle {
    pub fn load(
        lib_path: &str,
        is_server: bool,
        addr: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let syms = LoadedSymbols::open(lib_path)?;
        let node_handle = syms.start_node(is_server, addr)?;

        Ok(Self { syms, node_handle })
    }

    pub fn send(&self, data: &[u8]) -> i32 {
        self.syms.send(self.node_handle, data)
    }

    pub fn recv(&self, stream_idx: i32, buf: &mut [u8]) -> i32 {
        self.syms.recv(self.node_handle, stream_idx, buf)
    }

    pub fn io(&self) -> TransportIo<'_> {
        TransportIo::new(self)
    }
}

impl Drop for TransportHandle {
    fn drop(&mut self) {
        self.syms.stop(self.node_handle);
    }
}

pub struct TransportIo<'a> {
    transport: &'a TransportHandle,
    stream_idx: i32,
    buf: Vec<u8>,
    pos: usize,
}

impl<'a> TransportIo<'a> {
    pub fn new(transport: &'a TransportHandle) -> Self {
        Self {
            transport,
            stream_idx: 0,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl<'a> Read for TransportIo<'a> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.buf.len() {
            let mut frame = vec![0u8; 32 * 1024];
            let n = self.transport.recv(self.stream_idx, &mut frame);
            if n < 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "transport recv failed",
                ));
            }
            if n == 0 {
                return Ok(0);
            }
            frame.truncate(n as usize);
            self.buf = frame;
            self.pos = 0;
        }

        let available = self.buf.len() - self.pos;
        let to_copy = dst.len().min(available);
        dst[..to_copy].copy_from_slice(&self.buf[self.pos..self.pos + to_copy]);
        self.pos += to_copy;
        Ok(to_copy)
    }
}

impl<'a> Write for TransportIo<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ret = self.transport.send(buf);
        if ret < 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "transport send failed",
            ));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Drop for TransportIo<'a> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}
