mod handshake;

use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::raw::{c_char, c_int, c_uchar};
use std::sync::{Arc, Mutex};

use zeroize::Zeroize;

const BUF_SIZE: usize = 32 * 1024;
const MAX_HANDLES: usize = 64;

static HANDLES: Mutex<Vec<Option<Arc<Mutex<TcpStream>>>>> = Mutex::new(Vec::new());

fn alloc_handle(stream: TcpStream) -> c_int {
    let stream = Arc::new(Mutex::new(stream));
    let mut handles = match HANDLES.lock() {
        Ok(h) => h,
        Err(poisoned) => poisoned.into_inner(),
    };

    for (i, slot) in handles.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(stream);
            return i as c_int;
        }
    }

    if handles.len() >= MAX_HANDLES {
        return -1;
    }

    handles.push(Some(stream));
    (handles.len() - 1) as c_int
}

fn free_handle(handle: c_int) {
    if handle < 0 {
        return;
    }
    let mut handles = match HANDLES.lock() {
        Ok(h) => h,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(slot) = handles.get_mut(handle as usize)
        && let Some(stream) = slot.take()
        && let Ok(s) = stream.lock()
    {
        let _ = s.shutdown(Shutdown::Both);
    }
}

fn with_stream<F, R>(handle: c_int, f: F) -> Option<R>
where
    F: FnOnce(&mut TcpStream) -> R,
{
    if handle < 0 {
        return None;
    }
    let handles = HANDLES.lock().ok()?;
    let slot = handles.get(handle as usize)?;
    let stream = slot.as_ref()?;
    let mut guard = stream.lock().ok()?;
    Some(f(&mut guard))
}

fn send_frame(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let len = data.len();
    if len > u32::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "message too large"));
    }
    let len_bytes = (len as u32).to_be_bytes();
    stream.write_all(&len_bytes)?;
    stream.write_all(data)?;
    stream.flush()?;
    Ok(())
}

fn recv_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > BUF_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Convert a C string pointer to a Rust `&str` reference.
///
/// # Safety
///
/// `ptr` must be a valid null-terminated C string or null.
unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: Caller guarantees `ptr` points to a valid null-terminated C string.
    unsafe { CStr::from_ptr(ptr).to_str().ok() }
}

/// Create a byte slice from a raw pointer and length safely.
///
/// # Safety
///
/// `ptr` must point to `len` initialized, readable bytes if `len > 0`.
unsafe fn slice_from_ptr<'a>(ptr: *const c_uchar, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() && len > 0 {
        return None;
    }
    if len == 0 {
        return Some(&[]);
    }
    // SAFETY: Caller guarantees `ptr` points to `len` readable bytes.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Create a mutable byte slice from a raw pointer and length safely.
///
/// # Safety
///
/// `ptr` must point to `len` initialized, writable bytes if `len > 0`.
unsafe fn slice_from_ptr_mut<'a>(ptr: *mut c_uchar, len: usize) -> Option<&'a mut [u8]> {
    if ptr.is_null() && len > 0 {
        return None;
    }
    if len == 0 {
        return Some(&mut []);
    }
    // SAFETY: Caller guarantees `ptr` points to `len` writable bytes.
    Some(unsafe { std::slice::from_raw_parts_mut(ptr, len) })
}

/// Start a transport node (server or client).
///
/// # Safety
///
/// - `addr` must be a valid null-terminated C string pointer.
/// - `auth_key` must point to a 32-byte authorization key buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn StartNode(
    is_server: c_int,
    addr: *const c_char,
    auth_key: *const c_uchar,
) -> c_int {
    std::panic::catch_unwind(|| {
        // SAFETY: Delegating to `cstr_to_str` which verifies nullness.
        let addr_str = unsafe { cstr_to_str(addr) }.unwrap_or("0.0.0.0:9000");
        // SAFETY: Delegating to `slice_from_ptr` which verifies nullness.
        let key_slice = match unsafe { slice_from_ptr(auth_key, 32) } {
            Some(s) => s,
            None => return -1,
        };

        let mut key = [0u8; 32];
        key.copy_from_slice(key_slice);

        let result = if is_server != 0 {
            start_server(addr_str, &key)
        } else {
            start_client(addr_str, &key)
        };

        key.zeroize();
        result.unwrap_or(-1)
    })
    .unwrap_or(-1)
}

fn start_server(addr: &str, auth_key: &[u8; 32]) -> io::Result<c_int> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(false)?;

    let (mut stream, _) = listener.accept()?;
    handshake::server(&mut stream, auth_key)?;

    let handle = alloc_handle(stream);
    if handle < 0 {
        Err(io::Error::other("handle allocation failed"))
    } else {
        Ok(handle)
    }
}

fn start_client(addr: &str, auth_key: &[u8; 32]) -> io::Result<c_int> {
    let mut stream = TcpStream::connect(addr)?;
    handshake::client(&mut stream, auth_key)?;

    let handle = alloc_handle(stream);
    if handle < 0 {
        Err(io::Error::other("handle allocation failed"))
    } else {
        Ok(handle)
    }
}

/// Send a frame of data over the given node handle.
///
/// # Safety
///
/// `data` must point to `length` valid readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SendMessage(
    handle: c_int,
    data: *const c_uchar,
    length: c_int,
) -> c_int {
    std::panic::catch_unwind(|| {
        if length < 0 {
            return -1;
        }
        // SAFETY: Delegating to `slice_from_ptr`.
        let buf = match unsafe { slice_from_ptr(data, length as usize) } {
            Some(b) => b,
            None => return -1,
        };
        let ok = with_stream(handle, |stream| send_frame(stream, buf).is_ok());
        if ok == Some(true) {
            length
        } else {
            -1
        }
    })
    .unwrap_or(-1)
}

/// Receive a frame of data over the given node handle into `out_buf`.
///
/// # Safety
///
/// `out_buf` must point to `out_len` valid writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn RecvMessage(
    handle: c_int,
    _stream_idx: c_int,
    out_buf: *mut c_uchar,
    out_len: c_int,
) -> c_int {
    std::panic::catch_unwind(|| {
        if out_len < 0 {
            return -1;
        }
        // SAFETY: Delegating to `slice_from_ptr_mut`.
        let dst = match unsafe { slice_from_ptr_mut(out_buf, out_len as usize) } {
            Some(d) => d,
            None => return -1,
        };

        let result = with_stream(handle, recv_frame);
        match result {
            Some(Ok(mut frame)) => {
                let n = frame.len().min(dst.len());
                dst[..n].copy_from_slice(&frame[..n]);
                frame.zeroize();
                n as c_int
            }
            _ => -1,
        }
    })
    .unwrap_or(-1)
}

/// Stop a transport node and free its resources.
///
/// # Safety
///
/// `handle` must be a node handle created by `StartNode`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn StopNode(handle: c_int) {
    let _ = std::panic::catch_unwind(|| {
        free_handle(handle);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_handle_ops() {
        assert_eq!(with_stream(-1, |_| ()), None);
        assert_eq!(with_stream(999, |_| ()), None);
        // SAFETY: Invalid handle is gracefully handled.
        unsafe {
            StopNode(-1);
            StopNode(999);
        }
    }
}

