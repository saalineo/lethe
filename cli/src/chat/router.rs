use crate::ffi::transport::TransportHandle;
use std::sync::Arc;

pub struct HostRouter {
    transport: Arc<TransportHandle>,
}

impl HostRouter {
    pub fn new(transport: TransportHandle) -> Self {
        Self {
            transport: Arc::new(transport),
        }
    }

    pub fn fan_out(&self, ciphertext: &[u8]) {
        self.transport.send(ciphertext);
    }

    pub fn transport(&self) -> Arc<TransportHandle> {
        Arc::clone(&self.transport)
    }

    #[allow(dead_code)]
    pub fn inner(&self) -> Arc<TransportHandle> {
        self.transport()
    }
}
