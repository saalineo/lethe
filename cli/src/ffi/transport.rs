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
        auth_key: &[u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let syms = LoadedSymbols::open(lib_path)?;
        let node_handle = syms.start_node(is_server, addr, auth_key)?;

        Ok(Self { syms, node_handle })
    }

    pub fn send(&self, data: &[u8]) -> i32 {
        self.syms.send(self.node_handle, data)
    }

    pub fn recv(&self, stream_idx: i32, buf: &mut [u8]) -> i32 {
        self.syms.recv(self.node_handle, stream_idx, buf)
    }
}

impl Drop for TransportHandle {
    fn drop(&mut self) {
        self.syms.stop(self.node_handle);
    }
}
