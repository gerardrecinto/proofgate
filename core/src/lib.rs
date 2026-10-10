//! proofgate: exact semantic diff and invariant proofs for first-match access policies.

pub mod analyze;
pub mod model;
pub mod space;

use model::{err, Policy, Result};
use serde_json::{json, Value};

/// JSON in, JSON out. The CLI, the WebAssembly build and the tests all go through this.
pub fn run(op: &str, a: &str, b: &str) -> Result<Value> {
    fn to_value<T: serde::Serialize>(v: T) -> Result<Value> {
        serde_json::to_value(v).map_err(|e| model::PolicyError(e.to_string()))
    }
    match op {
        "check" => to_value(analyze::check(&Policy::parse(a)?)),
        "diff" => to_value(analyze::diff(&Policy::parse(a)?, &Policy::parse(b)?)?),
        _ => err(format!("unknown operation '{op}'")),
    }
}

/// Same as `run`, but never fails: errors come back as {"error": "..."}.
pub fn run_to_string(op: &str, a: &str, b: &str) -> String {
    match run(op, a, b) {
        Ok(v) => v.to_string(),
        Err(e) => json!({ "error": e.0 }).to_string(),
    }
}

/// WebAssembly entry points. JavaScript allocates with `pg_alloc`, writes UTF-8 into the
/// buffer, calls `pg_run`, reads the result with `pg_result_ptr` and `pg_result_len`.
#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::cell::RefCell;

    thread_local! {
        static OUT: RefCell<String> = const { RefCell::new(String::new()) };
    }

    #[no_mangle]
    pub extern "C" fn pg_alloc(len: usize) -> *mut u8 {
        let mut buf = Vec::<u8>::with_capacity(len);
        let ptr = buf.as_mut_ptr();
        std::mem::forget(buf);
        ptr
    }

    #[no_mangle]
    pub unsafe extern "C" fn pg_free(ptr: *mut u8, len: usize) {
        drop(Vec::from_raw_parts(ptr, 0, len));
    }

    /// op: 0 check, 1 diff.
    #[no_mangle]
    pub unsafe extern "C" fn pg_run(
        op: u32,
        a: *const u8,
        a_len: usize,
        b: *const u8,
        b_len: usize,
    ) {
        let read = |p: *const u8, n: usize| {
            String::from_utf8_lossy(std::slice::from_raw_parts(p, n)).into_owned()
        };
        let name = if op == 0 { "check" } else { "diff" };
        let out = super::run_to_string(name, &read(a, a_len), &read(b, b_len));
        OUT.with(|o| *o.borrow_mut() = out);
    }

    #[no_mangle]
    pub extern "C" fn pg_result_ptr() -> *const u8 {
        OUT.with(|o| o.borrow().as_ptr())
    }

    #[no_mangle]
    pub extern "C" fn pg_result_len() -> usize {
        OUT.with(|o| o.borrow().len())
    }
}
