use crate::ffi::transport::TransportHandle;
use std::sync::{Arc, RwLock};

pub struct HostRouter {
    transport: Arc<RwLock<TransportHandle>>,
}

impl HostRouter {
    pub fn new(transport: TransportHandle) -> Self {
        Self {
            transport: Arc::new(RwLock::new(transport)),
        }
    }

    pub fn fan_out(&self, ciphertext: &[u8]) {
        if let Ok(t) = self.transport.read() {
            t.send(ciphertext);
        }
    }

    pub fn inner(&self) -> Arc<RwLock<TransportHandle>> {
        Arc::clone(&self.transport)
    }
}
