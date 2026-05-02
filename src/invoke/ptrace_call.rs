// https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1
// https://youtu.be/0o8Ex8mXigU

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::ptr;

    use nix::sys::ptrace;
    use nix::sys::signal::Signal;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::{ForkResult, execvp, fork};

    use crate::invoke::types::{FfiType, FfiValue};

    // https://wiki.osdev.org/System_V_ABI#x86-64
    const MAX_REG_ARGS: usize = 6;

    pub fn invoke_ptrace(
        binary_path: &Path,
        addr: u64,
        args: &[(FfiType, FfiValue)],
        ret_type: &FfiType,
    ) -> Result<String, String> {
        if args.len() > MAX_REG_ARGS {
            return Err(format!(
                "ptrace invoke supports at most {MAX_REG_ARGS} arguments (x86_64 register ABI)"
            ));
        }

        let binary_cstr = std::ffi::CString::new(binary_path.to_string_lossy().as_bytes())
            .map_err(|e| format!("invalid binary path: {e}"))?;

        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                ptrace::traceme().expect("ptrace traceme failed");
                let args: [std::ffi::CString; 0] = [];
                execvp(&binary_cstr, &args).expect("execvp failed");
                unreachable!();
            }
            Ok(ForkResult::Parent { child }) => {
                match waitpid(child, None) {
                    Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {}
                    Ok(status) => return Err(format!("unexpected wait status: {status:?}")),
                    Err(e) => return Err(format!("waitpid failed: {e}")),
                }

                let mut regs = ptrace::getregs(child)
                    .map_err(|e| format!("getregs failed: {e}"))?;

                let arg_vals: Vec<u64> = args
                    .iter()
                    .map(|(_, v)| ffi_value_to_u64(v))
                    .collect::<Result<Vec<_>, _>>()?;

                // stuff args into registers (SysV x86_64)
                if arg_vals.len() > 0 { regs.rdi = arg_vals[0]; }
                if arg_vals.len() > 1 { regs.rsi = arg_vals[1]; }
                if arg_vals.len() > 2 { regs.rdx = arg_vals[2]; }
                if arg_vals.len() > 3 { regs.rcx = arg_vals[3]; }
                if arg_vals.len() > 4 { regs.r8 = arg_vals[4]; }
                if arg_vals.len() > 5 { regs.r9 = arg_vals[5]; }

                // plant int3 at entry point, push it as return addr so we catch the ret
                // https://stackoverflow.com/a/10409854
                regs.rsp -= 8;
                let trap_addr = regs.rsp;

                let original_word = ptrace::read(child, ptr::without_provenance_mut(regs.rip as usize))
                    .map_err(|e| format!("ptrace read failed: {e}"))?;

                unsafe {
                    ptrace::write(
                        child,
                        ptr::without_provenance_mut(regs.rip as usize),
                        0xCCi64 as *mut libc::c_void,
                    )
                    .map_err(|e| format!("ptrace write trap failed: {e}"))?;
                }

                unsafe {
                    ptrace::write(
                        child,
                        ptr::without_provenance_mut(trap_addr as usize),
                        regs.rip as i64 as *mut libc::c_void,
                    )
                    .map_err(|e| format!("ptrace write return addr failed: {e}"))?;
                }

                regs.rip = addr;
                ptrace::setregs(child, regs)
                    .map_err(|e| format!("setregs failed: {e}"))?;

                ptrace::cont(child, None)
                    .map_err(|e| format!("ptrace cont failed: {e}"))?;

                match waitpid(child, None) {
                    Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {}
                    Ok(WaitStatus::Exited(_, code)) => {
                        return Ok(format!("(process exited with code {code})"));
                    }
                    Ok(WaitStatus::Signaled(_, sig, _)) => {
                        return Err(format!("process killed by signal {sig}"));
                    }
                    Ok(status) => return Err(format!("unexpected status after cont: {status:?}")),
                    Err(e) => return Err(format!("waitpid after cont failed: {e}")),
                }

                let ret_regs = ptrace::getregs(child)
                    .map_err(|e| format!("getregs after call failed: {e}"))?;

                unsafe {
                    ptrace::write(
                        child,
                        ptr::without_provenance_mut(addr as usize),
                        original_word as *mut libc::c_void,
                    )
                    .ok();
                }

                let _ = nix::sys::signal::kill(child, Signal::SIGKILL);
                let _ = waitpid(child, None);

                format_return(ret_regs.rax, ret_type)
            }
            Err(e) => Err(format!("fork failed: {e}")),
        }
    }

    fn ffi_value_to_u64(v: &FfiValue) -> Result<u64, String> {
        match v {
            FfiValue::I32(x) => Ok(*x as u64),
            FfiValue::I64(x) => Ok(*x as u64),
            FfiValue::U32(x) => Ok(*x as u64),
            FfiValue::U64(x) => Ok(*x),
            FfiValue::Pointer(x) => Ok(*x as u64),
            // floats go in xmm regs, not worth the complexity rn
            FfiValue::F32(_) | FfiValue::F64(_) => {
                Err("float args not supported in ptrace mode (use dlopen invoke instead)".to_string())
            }
            FfiValue::CString(_) => {
                Err("string args not supported in ptrace mode".to_string())
            }
            FfiValue::Void => Err("void cannot be an argument".to_string()),
        }
    }

    fn format_return(rax: u64, ret_type: &FfiType) -> Result<String, String> {
        match ret_type {
            FfiType::I32 => Ok((rax as i32).to_string()),
            FfiType::I64 => Ok((rax as i64).to_string()),
            FfiType::U32 => Ok((rax as u32).to_string()),
            FfiType::U64 => Ok(rax.to_string()),
            FfiType::Pointer => Ok(format!("0x{rax:x}")),
            FfiType::Void => Ok("(void)".to_string()),
            FfiType::CString => Ok(format!("0x{rax:x} (string pointer)")),
            FfiType::F32 | FfiType::F64 => {
                Err("float return types not supported in ptrace mode".to_string())
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::invoke_ptrace;

#[cfg(not(target_os = "linux"))]
pub fn invoke_ptrace(
    _binary_path: &std::path::Path,
    _addr: u64,
    _args: &[(super::types::FfiType, super::types::FfiValue)],
    _ret_type: &super::types::FfiType,
) -> Result<String, String> {
    Err("ptrace invocation is only supported on Linux (x86_64)".to_string())
}
