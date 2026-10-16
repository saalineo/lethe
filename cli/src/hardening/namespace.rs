use libc::{
    mount, umount2, unshare, CLONE_NEWNS, CLONE_NEWUSER, MNT_DETACH, MS_NODEV, MS_NOEXEC,
    MS_NOSUID, MS_PRIVATE, MS_REC,
};
use std::ffi::CString;
use std::fs;
use std::ptr;

pub fn isolate_environment() -> Result<(), &'static str> {
    // SAFETY: Querying thread-safe OS uid/gid.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // SAFETY: Process isolation via unshare syscalls and namespace mounting.
    unsafe {
        if unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0 {
            return Err("Capability cap_sys_admin missing (failed unshare)");
        }

        let _ = fs::write("/proc/self/setgroups", b"deny");

        let uid_str = format!("0 {} 1", uid);
        let _ = fs::write("/proc/self/uid_map", uid_str.as_bytes());

        let gid_str = format!("0 {} 1", gid);
        let _ = fs::write("/proc/self/gid_map", gid_str.as_bytes());

        let root = CString::new("/").map_err(|_| "Invalid root path")?;
        if mount(
            ptr::null(),
            root.as_ptr(),
            ptr::null(),
            MS_PRIVATE | MS_REC,
            ptr::null(),
        ) != 0
        {
            return Err("Failed to mount private root");
        }

        let tmp_path = CString::new("/tmp").map_err(|_| "Invalid tmp path")?;
        let tmpfs = CString::new("tmpfs").map_err(|_| "Invalid tmpfs name")?;
        let flags = MS_NOSUID | MS_NOEXEC | MS_NODEV;

        // RAM-only scratch space for Tor state. `noswap` (Linux >= 6.4) keeps
        // tmpfs pages out of swap, which mlockall does not cover.
        let hardened = CString::new("size=192m,mode=0700,noswap").map_err(|_| "Invalid tmpfs options")?;
        let plain = CString::new("size=192m,mode=0700").map_err(|_| "Invalid tmpfs options")?;
        if mount(
            tmpfs.as_ptr(),
            tmp_path.as_ptr(),
            tmpfs.as_ptr(),
            flags,
            hardened.as_ptr() as *const _,
        ) != 0
        {
            // Older kernels reject `noswap` with EINVAL: retry and warn.
            if mount(
                tmpfs.as_ptr(),
                tmp_path.as_ptr(),
                tmpfs.as_ptr(),
                flags,
                plain.as_ptr() as *const _,
            ) == 0
            {
                crate::status_ln!(
                    "[!] kernel lacks tmpfs `noswap`: Tor state in /tmp may be swapped"
                );
            }
        }

        let proc_path = CString::new("/proc").map_err(|_| "Invalid proc path")?;
        let proc_fs = CString::new("proc").map_err(|_| "Invalid proc fs name")?;

        umount2(proc_path.as_ptr(), MNT_DETACH);
        mount(
            proc_fs.as_ptr(),
            proc_path.as_ptr(),
            proc_fs.as_ptr(),
            flags,
            ptr::null(),
        );
    }
    Ok(())
}
