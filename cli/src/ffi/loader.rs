use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_uchar};

use libloading::{Library, Symbol};

type FnStartNode = unsafe extern "C" fn(c_int, *const c_char) -> c_int;
type FnSendMessage = unsafe extern "C" fn(c_int, *const c_uchar, c_int) -> c_int;
type FnRecvMessage = unsafe extern "C" fn(c_int, c_int, *mut c_uchar, c_int) -> c_int;
type FnStopNode = unsafe extern "C" fn(c_int);

pub struct LoadedSymbols {
    pub _lib: Library,
    pub start_node: FnStartNode,
    pub send_message: FnSendMessage,
    pub recv_message: FnRecvMessage,
    pub stop_node: FnStopNode,
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

        Ok(Self {
            _lib: lib,
            start_node,
            send_message,
            recv_message,
            stop_node,
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
