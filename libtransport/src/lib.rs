use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::raw::{c_char, c_int, c_uchar};
use std::sync::{Arc, Mutex};

use zeroize::Zeroize;

const BUF_SIZE: usize = 32 * 1024;
const MAX_HANDLES: usize = 64;

struct Conn {
    rd: Mutex<TcpStream>,
    wr: Mutex<TcpStream>,
    ctl: TcpStream,
}

impl Conn {
    fn new(stream: TcpStream) -> io::Result<Self> {
        let wr = stream.try_clone()?;
        let ctl = stream.try_clone()?;
        Ok(Self {
            rd: Mutex::new(stream),
            wr: Mutex::new(wr),
            ctl,
        })
    }

    fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut wr = self.wr.lock().unwrap_or_else(|p| p.into_inner());
        send_frame(&mut wr, data)
    }

    fn recv(&self) -> io::Result<Vec<u8>> {
        let mut rd = self.rd.lock().unwrap_or_else(|p| p.into_inner());
        recv_frame(&mut rd)
    }

    fn shutdown(&self) {
        let _ = self.ctl.shutdown(Shutdown::Both);
    }
}

static HANDLES: Mutex<Vec<Option<Arc<Conn>>>> = Mutex::new(Vec::new());

fn alloc_handle(stream: TcpStream) -> io::Result<c_int> {
    let conn = Arc::new(Conn::new(stream)?);
    let mut handles = HANDLES.lock().unwrap_or_else(|p| p.into_inner());

    let idx = match handles.iter().position(Option::is_none) {
        Some(i) => i,
        None if handles.len() < MAX_HANDLES => {
            handles.push(None);
            handles.len() - 1
        }
        None => return Err(io::Error::other("handle table full")),
    };

    handles[idx] = Some(conn);
    Ok(idx as c_int)
}

/// Retrieve a clone of `Arc<Conn>`.
///
/// Crucially, the global `HANDLES` table lock is released prior to returning,
/// preventing global contention and deadlocks during subsequent I/O.
fn conn(handle: c_int) -> Option<Arc<Conn>> {
    if handle < 0 {
        return None;
    }
    let handles = HANDLES.lock().unwrap_or_else(|p| p.into_inner());
    handles
        .get(handle as usize)
        .and_then(|slot| slot.as_ref().cloned())
}

/// Free a handle, clearing its slot for reuse and shutting down socket I/O.
///
/// Uses `ctl.shutdown(Shutdown::Both)` without acquiring `rd` or `wr` mutexes,
/// ensuring any reader blocked on `read_exact` unblocks immediately.
fn free_handle(handle: c_int) {
    if handle < 0 {
        return;
    }
    let conn = {
        let mut handles = HANDLES.lock().unwrap_or_else(|p| p.into_inner());
        handles
            .get_mut(handle as usize)
            .and_then(|slot| slot.take())
    };

    if let Some(c) = conn {
        c.shutdown();
    }
}

fn send_frame(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let len = data.len();
    if len > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "message too large",
        ));
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
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn StartNode(is_server: c_int, addr: *const c_char) -> c_int {
    std::panic::catch_unwind(|| {
        // SAFETY: Delegating to `cstr_to_str` which verifies nullness.
        let addr_str = unsafe { cstr_to_str(addr) }.unwrap_or("0.0.0.0:9000");

        let result = if is_server != 0 {
            start_server(addr_str)
        } else {
            start_client(addr_str)
        };

        result.unwrap_or(-1)
    })
    .unwrap_or(-1)
}

fn start_server(addr: &str) -> io::Result<c_int> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(false)?;

    let (stream, _) = listener.accept()?;
    alloc_handle(stream)
}

fn start_client(addr: &str) -> io::Result<c_int> {
    let stream = TcpStream::connect(addr)?;
    alloc_handle(stream)
}

/// Send a frame of data over the given node handle.
///
/// # Safety
///
/// `data` must point to `length` valid readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SendMessage(handle: c_int, data: *const c_uchar, length: c_int) -> c_int {
    std::panic::catch_unwind(|| {
        if length < 0 {
            return -1;
        }
        // SAFETY: Delegating to `slice_from_ptr`.
        let buf = match unsafe { slice_from_ptr(data, length as usize) } {
            Some(b) => b,
            None => return -1,
        };
        let conn = match conn(handle) {
            Some(c) => c,
            None => return -1,
        };
        if conn.send(buf).is_ok() { length } else { -1 }
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
        let conn = match conn(handle) {
            Some(c) => c,
            None => return -1,
        };
        match conn.recv() {
            Ok(mut frame) => {
                let n = frame.len().min(dst.len());
                dst[..n].copy_from_slice(&frame[..n]);
                frame.zeroize();
                n as c_int
            }
            Err(_) => -1,
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_test() -> std::sync::MutexGuard<'static, ()> {
        match TEST_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    #[test]
    fn test_invalid_handle_ops() {
        let _guard = lock_test();
        assert!(conn(-1).is_none());
        assert!(conn(999).is_none());
        // SAFETY: Invalid handle is gracefully handled.
        unsafe {
            assert_eq!(SendMessage(-1, std::ptr::null(), 0), -1);
            assert_eq!(SendMessage(999, std::ptr::null(), 0), -1);
            assert_eq!(RecvMessage(-1, 0, std::ptr::null_mut(), 0), -1);
            assert_eq!(RecvMessage(999, 0, std::ptr::null_mut(), 0), -1);
            StopNode(-1);
            StopNode(999);
        }
    }

    #[test]
    fn test_handle_table_lifecycle_and_recycling() {
        let _guard = lock_test();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let s1 = TcpStream::connect(addr).unwrap();
        let _server_conn = listener.accept().unwrap();
        let h1 = alloc_handle(s1).unwrap();
        assert!(h1 >= 0);

        let s2 = TcpStream::connect(addr).unwrap();
        let _server_conn2 = listener.accept().unwrap();
        let h2 = alloc_handle(s2).unwrap();
        assert!(h2 >= 0);
        assert_ne!(h1, h2);

        // Free h1
        free_handle(h1);
        assert!(conn(h1).is_none());

        // Allocate again, it should recycle h1's slot (D15)
        let s3 = TcpStream::connect(addr).unwrap();
        let _server_conn3 = listener.accept().unwrap();
        let h3 = alloc_handle(s3).unwrap();
        assert_eq!(h1, h3);

        free_handle(h2);
        free_handle(h3);
    }

    #[test]
    fn test_handle_table_saturation() {
        let _guard = lock_test();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut handles = Vec::new();
        // Allocate up to MAX_HANDLES
        for _ in 0..MAX_HANDLES {
            let client = TcpStream::connect(addr).unwrap();
            let _server = listener.accept().unwrap();
            match alloc_handle(client) {
                Ok(h) => handles.push(h),
                Err(_) => break,
            }
        }

        // Table should now be saturated
        let overflow_client = TcpStream::connect(addr).unwrap();
        let _overflow_server = listener.accept().unwrap();
        assert!(alloc_handle(overflow_client).is_err());

        // Free one handle and verify we can allocate again
        if let Some(h) = handles.pop() {
            free_handle(h);
            let retry_client = TcpStream::connect(addr).unwrap();
            let _retry_server = listener.accept().unwrap();
            let new_h = alloc_handle(retry_client).unwrap();
            assert_eq!(new_h, h);
            handles.push(new_h);
        }

        // Cleanup all allocated handles
        for h in handles {
            free_handle(h);
        }
    }

    #[test]
    fn test_full_duplex_concurrency() {
        let _guard = lock_test();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            alloc_handle(stream).unwrap()
        });

        let client_stream = TcpStream::connect(addr).unwrap();
        let client_handle = alloc_handle(client_stream).unwrap();
        let server_handle = server_thread.join().unwrap();

        let msg_a_to_b = b"hello from client to server";
        let msg_b_to_a = b"greetings from server to client";

        // Spawn concurrent threads to simultaneously receive in both directions
        let t_client_recv = thread::spawn(move || {
            let mut buf = [0u8; 128];
            // SAFETY: Valid buffer pointer and length
            let n = unsafe { RecvMessage(client_handle, 0, buf.as_mut_ptr(), buf.len() as c_int) };
            assert_eq!(n, msg_b_to_a.len() as c_int);
            assert_eq!(&buf[..n as usize], msg_b_to_a);
        });

        let t_server_recv = thread::spawn(move || {
            let mut buf = [0u8; 128];
            // SAFETY: Valid buffer pointer and length
            let n = unsafe { RecvMessage(server_handle, 0, buf.as_mut_ptr(), buf.len() as c_int) };
            assert_eq!(n, msg_a_to_b.len() as c_int);
            assert_eq!(&buf[..n as usize], msg_a_to_b);
        });

        // Small delay to ensure both receivers are blocked waiting on RecvMessage
        thread::sleep(Duration::from_millis(50));

        // Simultaneous sends from both sides while receivers are blocked
        // SAFETY: Valid buffer pointer and length
        let sent_c = unsafe {
            SendMessage(
                client_handle,
                msg_a_to_b.as_ptr(),
                msg_a_to_b.len() as c_int,
            )
        };
        assert_eq!(sent_c, msg_a_to_b.len() as c_int);

        // SAFETY: Valid buffer pointer and length
        let sent_s = unsafe {
            SendMessage(
                server_handle,
                msg_b_to_a.as_ptr(),
                msg_b_to_a.len() as c_int,
            )
        };
        assert_eq!(sent_s, msg_b_to_a.len() as c_int);

        t_client_recv.join().unwrap();
        t_server_recv.join().unwrap();

        // SAFETY: Cleaning up test handles
        unsafe {
            StopNode(client_handle);
            StopNode(server_handle);
        }
    }

    #[test]
    fn test_shutdown_unblocks_blocked_reader() {
        let _guard = lock_test();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            alloc_handle(stream).unwrap()
        });

        let client_stream = TcpStream::connect(addr).unwrap();
        let client_handle = alloc_handle(client_stream).unwrap();
        let server_handle = server_thread.join().unwrap();

        let reader_unblocked = Arc::new(AtomicBool::new(false));
        let reader_flag = Arc::clone(&reader_unblocked);

        let reader_thread = thread::spawn(move || {
            let mut buf = [0u8; 64];
            // RecvMessage will block because server sends nothing
            // SAFETY: Valid buffer pointer and length
            let n = unsafe { RecvMessage(client_handle, 0, buf.as_mut_ptr(), buf.len() as c_int) };
            assert_eq!(n, -1);
            reader_flag.store(true, Ordering::SeqCst);
        });

        // Wait to make sure reader is blocked in RecvMessage
        thread::sleep(Duration::from_millis(50));
        assert!(!reader_unblocked.load(Ordering::SeqCst));

        // StopNode should call ctl.shutdown without needing rd lock, unblocking reader immediately
        // SAFETY: Free client handle
        unsafe {
            StopNode(client_handle);
        }

        reader_thread.join().unwrap();
        assert!(reader_unblocked.load(Ordering::SeqCst));

        // SAFETY: Clean up server handle
        unsafe {
            StopNode(server_handle);
        }
    }
}
