use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uchar};

use libloading::{Library, Symbol};

type FnStartNode = unsafe extern "C" fn(c_int, *const c_char) -> c_int;
type FnSendMessage = unsafe extern "C" fn(c_int, *const c_uchar, c_int) -> c_int;
type FnRecvMessage = unsafe extern "C" fn(c_int, c_int, *mut c_uchar, c_int) -> c_int;
type FnStopNode = unsafe extern "C" fn(c_int);
type FnStartOnion = unsafe extern "C" fn(c_int, *const c_char) -> c_int;
type FnOnionAddress = unsafe extern "C" fn(c_int, *mut c_uchar, c_int) -> c_int;
type FnWaitPeer = unsafe extern "C" fn(c_int) -> c_int;

pub struct LoadedSymbols {
    pub _lib: Library,
    pub start_node: FnStartNode,
    pub send_message: FnSendMessage,
    pub recv_message: FnRecvMessage,
    pub stop_node: FnStopNode,
    pub start_onion: FnStartOnion,
    pub onion_address: FnOnionAddress,
    pub wait_peer: FnWaitPeer,
}

impl LoadedSymbols {
    pub fn open(lib_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // SAFETY: Loading dynamic library from user/config provided path.
        let lib = unsafe { Library::new(lib_path)? };

        // SAFETY: Dereferencing loaded function pointers from dynamic library.
        let start_node: FnStartNode = unsafe {
            let sym: Symbol<FnStartNode> = lib.get(b"StartNode\0")?;
            *sym
        };
        let send_message: FnSendMessage = unsafe {
            let sym: Symbol<FnSendMessage> = lib.get(b"SendMessage\0")?;
            *sym
        };
        let recv_message: FnRecvMessage = unsafe {
            let sym: Symbol<FnRecvMessage> = lib.get(b"RecvMessage\0")?;
            *sym
        };
        let stop_node: FnStopNode = unsafe {
            let sym: Symbol<FnStopNode> = lib.get(b"StopNode\0")?;
            *sym
        };

        let start_onion: FnStartOnion = unsafe {
            let sym: Symbol<FnStartOnion> = lib.get(b"StartOnion\0")?;
            *sym
        };
        let onion_address: FnOnionAddress = unsafe {
            let sym: Symbol<FnOnionAddress> = lib.get(b"OnionAddress\0")?;
            *sym
        };
        let wait_peer: FnWaitPeer = unsafe {
            let sym: Symbol<FnWaitPeer> = lib.get(b"WaitPeer\0")?;
            *sym
        };

        Ok(Self {
            _lib: lib,
            start_node,
            send_message,
            recv_message,
            stop_node,
            start_onion,
            onion_address,
            wait_peer,
        })
    }

    pub fn start_node(
        &self,
        is_server: bool,
        addr: &str,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        let c_addr = CString::new(addr)?;
        // SAFETY: Invoking C function pointer with valid pointer parameters.
        let handle = unsafe { (self.start_node)(if is_server { 1 } else { 0 }, c_addr.as_ptr()) };
        if handle < 0 {
            return Err("StartNode returned error".into());
        }
        Ok(handle)
    }

    /// Bootstraps Tor (and publishes the service for a server); never waits for a peer.
    pub fn start_onion(
        &self,
        is_server: bool,
        peer_onion: Option<&str>,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        let c_peer = peer_onion.map(CString::new).transpose()?;
        let ptr = c_peer.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        // SAFETY: `ptr` is null or a valid NUL-terminated string kept alive above.
        let handle = unsafe { (self.start_onion)(if is_server { 1 } else { 0 }, ptr) };
        if handle < 0 {
            return Err("Tor bootstrap failed".into());
        }
        Ok(handle)
    }

    pub fn onion_address(&self, node_handle: c_int) -> Option<String> {
        let mut buf = [0u8; 128];
        // SAFETY: valid writable buffer of the stated capacity.
        let n = unsafe { (self.onion_address)(node_handle, buf.as_mut_ptr(), buf.len() as c_int) };
        if n <= 0 {
            return None;
        }
        std::str::from_utf8(&buf[..n as usize]).ok().map(str::to_owned)
    }

    pub fn wait_peer(&self, node_handle: c_int) -> bool {
        // SAFETY: handle came from `start_onion`.
        unsafe { (self.wait_peer)(node_handle) == 0 }
    }

    pub fn send(&self, node_handle: c_int, data: &[u8]) -> i32 {
        // SAFETY: Passing valid slice pointer and length to FFI function.
        unsafe { (self.send_message)(node_handle, data.as_ptr(), data.len() as c_int) }
    }

    pub fn recv(&self, node_handle: c_int, stream_idx: i32, buf: &mut [u8]) -> i32 {
        // SAFETY: Passing valid mutable slice pointer and length to FFI function.
        unsafe {
            (self.recv_message)(
                node_handle,
                stream_idx,
                buf.as_mut_ptr(),
                buf.len() as c_int,
            )
        }
    }

    pub fn stop(&self, node_handle: c_int) {
        // SAFETY: StopNode handle release.
        unsafe { (self.stop_node)(node_handle) }
    }
}
