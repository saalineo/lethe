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

    /// Tor path: bootstraps and (server) publishes the service, but does not wait for a peer.
    pub fn load_onion(
        lib_path: &str,
        is_server: bool,
        peer_onion: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let syms = LoadedSymbols::open(lib_path)?;
        let node_handle = syms.start_onion(is_server, peer_onion)?;
        Ok(Self { syms, node_handle })
    }

    /// Server only: the `<56>.onion` address.
    pub fn onion_address(&self) -> Option<String> {
        self.syms.onion_address(self.node_handle)
    }

    /// Blocks until the Tor stream is established.
    pub fn wait_peer(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.syms.wait_peer(self.node_handle) {
            Ok(())
        } else {
            Err("no peer connected over Tor".into())
        }
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
