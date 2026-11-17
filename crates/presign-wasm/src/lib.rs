//! WebAssembly entry points, callable from JavaScript without bindings.
//!
//! The host copies a UTF-8 JSON request into memory from [`presign_alloc`],
//! calls [`presign_analyze`], reads the JSON reply from the returned pointer
//! and length (packed as `ptr << 32 | len`), then releases both buffers with
//! [`presign_free`]. The reply is `{"ok": report}` or `{"error": message}`.

use serde_json::{Value, json};

/// Analyzes a request given as JSON text and returns the reply as JSON text.
pub fn analyze_json(input: &[u8]) -> String {
    let reply = serde_json::from_slice::<Value>(input)
        .map_err(|e| format!("invalid JSON: {e}"))
        .and_then(|req| presign::analyze(&req));
    match reply {
        Ok(report) => json!({"ok": report.to_json()}),
        Err(e) => json!({"error": e}),
    }
    .to_string()
}

/// Allocates `len` bytes for the host to write into.
#[unsafe(no_mangle)]
pub extern "C" fn presign_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Frees a buffer from [`presign_alloc`] or [`presign_analyze`].
///
/// # Safety
/// `ptr` and `len` must come from one of those calls and be freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn presign_free(ptr: *mut u8, len: usize) {
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len) });
}

/// # Safety
/// `ptr` must point to `len` initialized bytes from [`presign_alloc`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn presign_analyze(ptr: *const u8, len: usize) -> u64 {
    let input = unsafe { std::slice::from_raw_parts(ptr, len) };
    let mut out = analyze_json(input).into_bytes();
    out.shrink_to_fit();
    let (out_ptr, out_len) = (out.as_mut_ptr(), out.len());
    std::mem::forget(out);
    ((out_ptr as u64) << 32) | out_len as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_with_ok_or_error() {
        let ok: Value = serde_json::from_str(&analyze_json(
            br#"{"method":"eth_sign","params":["0x5b38da6a701c568545dcfcb03fcb875f56beddc4","0x00"]}"#,
        ))
        .unwrap();
        assert_eq!(ok["ok"]["verdict"], "critical");
        let err: Value = serde_json::from_str(&analyze_json(b"{")).unwrap();
        assert!(err["error"].as_str().unwrap().starts_with("invalid JSON"));
    }
}
