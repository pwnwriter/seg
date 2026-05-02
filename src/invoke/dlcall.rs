// https://users.rust-lang.org/t/load-shared-libraries-at-runtime/14419/3

use std::path::Path;

use libffi::middle::{Cif, CodePtr};

use super::types::{FfiType, FfiValue};

pub fn invoke_dl(
    lib_path: &Path,
    func_name: &str,
    args: &[(FfiType, FfiValue)],
    ret_type: &FfiType,
) -> Result<String, String> {
    let lib = unsafe { libloading::Library::new(lib_path) }
        .map_err(|e| format!("failed to load library '{}': {e}", lib_path.display()))?;

    let sym: libloading::Symbol<*const ()> = unsafe { lib.get(func_name.as_bytes()) }
        .map_err(|e| format!("symbol '{func_name}' not found: {e}"))?;

    let code_ptr = CodePtr::from_ptr(*sym as *const _);

    let arg_types: Vec<_> = args.iter().map(|(t, _)| t.to_libffi_type()).collect();
    let cif = Cif::new(arg_types, ret_type.to_libffi_type());
    let ffi_args: Vec<_> = args.iter().map(|(_, v)| v.to_libffi_arg()).collect();

    let result = match ret_type {
        FfiType::I32 => {
            let r: i32 = unsafe { cif.call(code_ptr, &ffi_args) };
            r.to_string()
        }
        FfiType::I64 => {
            let r: i64 = unsafe { cif.call(code_ptr, &ffi_args) };
            r.to_string()
        }
        FfiType::U32 => {
            let r: u32 = unsafe { cif.call(code_ptr, &ffi_args) };
            r.to_string()
        }
        FfiType::U64 => {
            let r: u64 = unsafe { cif.call(code_ptr, &ffi_args) };
            r.to_string()
        }
        FfiType::F32 => {
            let r: f32 = unsafe { cif.call(code_ptr, &ffi_args) };
            format!("{r}")
        }
        FfiType::F64 => {
            let r: f64 = unsafe { cif.call(code_ptr, &ffi_args) };
            format!("{r}")
        }
        FfiType::CString => {
            let r: *const libc::c_char = unsafe { cif.call(code_ptr, &ffi_args) };
            if r.is_null() {
                "(null)".to_string()
            } else {
                let cstr = unsafe { std::ffi::CStr::from_ptr(r) };
                cstr.to_string_lossy().to_string()
            }
        }
        FfiType::Pointer => {
            let r: *const () = unsafe { cif.call(code_ptr, &ffi_args) };
            format!("{r:#x?}")
        }
        FfiType::Void => {
            unsafe { cif.call::<()>(code_ptr, &ffi_args) };
            "(void)".to_string()
        }
    };

    Ok(result)
}
