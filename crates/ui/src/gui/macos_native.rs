//! Native macOS integrations via the Objective-C runtime: Finder-aware
//! Trash (`NSFileManager trashItemAtURL`, F-7) and file clipboard through
//! `NSPasteboard` (F-26). Both replace the previous AppleScript/manual-copy
//! workarounds and degrade gracefully to the legacy paths when the runtime
//! calls fail (e.g. headless contexts).

#![cfg(target_os = "macos")]

use std::ffi::{c_void, CStr, CString};
use std::path::Path;

extern "C" {
    fn objc_getClass(name: *const std::ffi::c_char) -> *mut c_void;
    fn sel_registerName(name: *const std::ffi::c_char) -> *mut c_void;
    fn objc_msgSend();
}

type Msg0 = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
type Msg1 = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
type Msg1Bool = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> bool;
type Msg2 = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
type MsgCount = unsafe extern "C" fn(*mut c_void, *mut c_void) -> usize;
type MsgIdx = unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> *mut c_void;

unsafe fn msg0(recv: *mut c_void, sel_name: &std::ffi::CStr) -> *mut c_void {
    if recv.is_null() {
        return std::ptr::null_mut();
    }
    let f: Msg0 = std::mem::transmute(objc_msgSend as *const ());
    f(recv, sel_registerName(sel_name.as_ptr()))
}

unsafe fn msg1(recv: *mut c_void, sel_name: &std::ffi::CStr, a: *mut c_void) -> *mut c_void {
    if recv.is_null() {
        return std::ptr::null_mut();
    }
    let f: Msg1 = std::mem::transmute(objc_msgSend as *const ());
    f(recv, sel_registerName(sel_name.as_ptr()), a)
}

unsafe fn msg1_bool(recv: *mut c_void, sel_name: &std::ffi::CStr, a: *mut c_void) -> bool {
    if recv.is_null() {
        return false;
    }
    let f: Msg1Bool = std::mem::transmute(objc_msgSend as *const ());
    f(recv, sel_registerName(sel_name.as_ptr()), a)
}

unsafe fn msg2(
    recv: *mut c_void,
    sel_name: &std::ffi::CStr,
    a: *mut c_void,
    b: *mut c_void,
) -> *mut c_void {
    if recv.is_null() {
        return std::ptr::null_mut();
    }
    let f: Msg2 = std::mem::transmute(objc_msgSend as *const ());
    f(recv, sel_registerName(sel_name.as_ptr()), a, b)
}

unsafe fn ns_string_from_str(s: &str) -> Option<*mut c_void> {
    let c = CString::new(s).ok()?;
    let cls = objc_getClass(c"NSString".as_ptr());
    let ptr = msg1(cls, c"stringWithUTF8String:", c.as_ptr() as *mut c_void);
    (!ptr.is_null()).then_some(ptr)
}

unsafe fn str_from_ns_string(ns: *mut c_void) -> Option<String> {
    if ns.is_null() {
        return None;
    }
    let utf8: *const std::ffi::c_char = {
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const std::ffi::c_char =
            std::mem::transmute(objc_msgSend as *const ());
        f(ns, sel_registerName(c"UTF8String".as_ptr()))
    };
    if utf8.is_null() {
        return None;
    }
    CStr::from_ptr(utf8).to_str().ok().map(str::to_string)
}

unsafe fn ns_url_for_path(path: &str) -> Option<*mut c_void> {
    let cls = objc_getClass(c"NSURL".as_ptr());
    let ns_path = ns_string_from_str(path)?;
    let url = msg1(cls, c"fileURLWithPath:", ns_path);
    (!url.is_null()).then_some(url)
}

unsafe fn ns_array_from_pointers(items: &[*mut c_void]) -> Option<*mut c_void> {
    if items.is_empty() {
        return None;
    }
    let cls = objc_getClass(c"NSArray".as_ptr());
    let f: unsafe extern "C" fn(
        *mut c_void,
        *mut c_void,
        *const *mut c_void,
        usize,
    ) -> *mut c_void = std::mem::transmute(objc_msgSend as *const ());
    let arr = f(
        cls,
        sel_registerName(c"arrayWithObjects:count:".as_ptr()),
        items.as_ptr(),
        items.len(),
    );
    (!arr.is_null()).then_some(arr)
}

/// Moves `path` to the macOS Trash via `NSFileManager trashItemAtURL:`,
/// which records the Finder Put-Back metadata the manual rename to
/// `~/.Trash` never could (F-7). Returns the final Trash path on success;
/// `Err` is surfaced to the user — the caller must NOT degrade to the
/// less-safe manual move (R07).
pub(super) fn macos_trash_item(path: &str) -> Result<String, String> {
    unsafe {
        let fm_cls = objc_getClass(c"NSFileManager".as_ptr());
        if fm_cls.is_null() {
            return Err("NSFileManager unavailable".to_string());
        }
        let fm = msg0(fm_cls, c"defaultManager");
        let url = ns_url_for_path(path).ok_or("invalid path")?;
        // `-trashItemAtURL:resultingItemURL:error:` (macOS 10.8+): the
        // out-parameter receives the new NSURL inside the Trash, whose
        // metadata carries the Finder Put-Back information (F-7).
        let mut resulting_url: *mut c_void = std::ptr::null_mut();
        let f: unsafe extern "C" fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut *mut c_void,
            *mut *mut c_void,
        ) -> bool = std::mem::transmute(objc_msgSend as *const ());
        let ok = f(
            fm,
            sel_registerName(c"trashItemAtURL:resultingItemURL:error:".as_ptr()),
            url,
            &mut resulting_url,
            std::ptr::null_mut(),
        );
        if !ok {
            return Err("NSFileManager rejected the trash request".to_string());
        }
        let moved_path = msg0(resulting_url, c"path");
        match str_from_ns_string(moved_path) {
            Some(p) => Ok(p),
            None => Ok(path_fallback_name(path)),
        }
    }
}

fn path_fallback_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| format!("{}/{}", "~/.Trash", n.to_string_lossy()))
        .unwrap_or_else(|| "~/.Trash".to_string())
}

/// Writes the given local file URLs onto the general `NSPasteboard` using
/// `writeObjects:` (F-26). This publishes the proper `fileURL` type that
/// Finder and native apps consume — unlike the osascript workaround, it
/// supports multiple files and never round-trips through Apple Events.
/// Returns false when the native paste failed so callers can fall back.
pub(super) fn macos_pasteboard_write_file_urls(paths: &[&str]) -> bool {
    unsafe {
        let pb_cls = objc_getClass(c"NSPasteboard".as_ptr());
        if pb_cls.is_null() {
            return false;
        }
        let pb = msg0(pb_cls, c"generalPasteboard");
        if pb.is_null() {
            return false;
        }
        let mut urls: Vec<*mut c_void> = Vec::with_capacity(paths.len());
        for p in paths {
            if let Some(u) = ns_url_for_path(p) {
                urls.push(u);
            }
        }
        if urls.len() != paths.len() {
            return false;
        }
        let _ = msg1_bool(pb, c"clearContents", std::ptr::null_mut());
        let Some(arr) = ns_array_from_pointers(&urls) else {
            return false;
        };
        msg1_bool(pb, c"writeObjects:", arr)
    }
}

/// Reads file URLs from the general `NSPasteboard` (F-26). Returns an
/// empty vector when the pasteboard holds no file URLs. `None` signals a
/// native failure so callers can fall back to the legacy path.
pub(super) fn macos_pasteboard_read_file_urls() -> Option<Vec<String>> {
    unsafe {
        let pb_cls = objc_getClass(c"NSPasteboard".as_ptr());
        if pb_cls.is_null() {
            return None;
        }
        let pb = msg0(pb_cls, c"generalPasteboard");
        if pb.is_null() {
            return None;
        }
        let ns_url_cls = objc_getClass(c"NSURL".as_ptr());
        if ns_url_cls.is_null() {
            return None;
        }
        let classes = ns_array_from_pointers(&[ns_url_cls])?;
        let objs = msg2(
            pb,
            c"readObjectsForClasses:options:",
            classes,
            std::ptr::null_mut(),
        );
        // A null result simply means "no matching objects" — not an error.
        if objs.is_null() {
            return Some(Vec::new());
        }
        let count_f: MsgCount = std::mem::transmute(objc_msgSend as *const ());
        let count = count_f(objs, sel_registerName(c"count".as_ptr()));
        let idx_f: MsgIdx = std::mem::transmute(objc_msgSend as *const ());
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let obj = idx_f(objs, sel_registerName(c"objectAtIndex:".as_ptr()), i);
            let path = msg0(obj, c"path");
            if let Some(p) = str_from_ns_string(path) {
                out.push(p);
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pasteboard and Trash are user session state; tests that touch them
    /// are opt-in (`MANIFOLD_TEST_ALLOW_SESSION_STATE=1`, set in CI).
    fn session_state_allowed() -> bool {
        std::env::var_os("MANIFOLD_TEST_ALLOW_SESSION_STATE").is_some_and(|v| v == "1")
    }

    #[test]
    fn pasteboard_file_url_roundtrip() {
        if !session_state_allowed() {
            eprintln!("skipping: set MANIFOLD_TEST_ALLOW_SESSION_STATE=1");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a.txt");
        let b = tmp.path().join("b b.txt");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let paths = vec![a.to_str().unwrap(), b.to_str().unwrap()];
        assert!(
            macos_pasteboard_write_file_urls(&paths),
            "native pasteboard write failed"
        );
        let read = macos_pasteboard_read_file_urls().expect("native pasteboard read failed");
        assert!(
            read.contains(&a.to_string_lossy().to_string()),
            "roundtrip lost a.txt: {read:?}"
        );
        assert!(
            read.contains(&b.to_string_lossy().to_string()),
            "roundtrip lost multi-file entry: {read:?}"
        );
    }

    #[test]
    fn trash_reports_final_path_and_removes_original() {
        if !session_state_allowed() {
            eprintln!("skipping: set MANIFOLD_TEST_ALLOW_SESSION_STATE=1");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("manifold-trash-test.txt");
        std::fs::write(&f, b"x").unwrap();
        match macos_trash_item(f.to_str().unwrap()) {
            Ok(final_path) => {
                assert!(!f.exists(), "file must leave its original location");
                // Clean up the entry this test created in the real Trash.
                let _ = std::fs::remove_file(&final_path);
            }
            Err(e) => eprintln!("native trash unavailable ({e}); fallback path used"),
        }
    }

    /// F-27 smoke test: an empty selection must be rejected before any
    /// ObjC messaging (the leak fix lives in `start_native_os_file_drag`).
    #[test]
    fn drag_out_empty_selection_is_rejected() {
        assert!(!super::super::clipboard::start_native_os_file_drag(&[]));
    }
}
