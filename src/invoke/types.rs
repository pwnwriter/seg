use std::ffi::CString;

use libffi::middle::{Arg, Type};

#[derive(Debug, Clone)]
pub enum FfiType {
    I32,
    I64,
    U32,
    U64,
    F32,
    F64,
    CString,
    Pointer,
    Void,
}

#[derive(Debug)]
pub enum FfiValue {
    I32(i32),
    I64(i64),
    U32(u32),
    U64(u64),
    F32(f32),
    F64(f64),
    CString(CString),
    Pointer(usize),
    Void,
}

impl FfiType {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "i32" => Ok(Self::I32),
            "i64" => Ok(Self::I64),
            "u32" => Ok(Self::U32),
            "u64" => Ok(Self::U64),
            "f32" => Ok(Self::F32),
            "f64" => Ok(Self::F64),
            "string" => Ok(Self::CString),
            "pointer" | "ptr" => Ok(Self::Pointer),
            "void" => Ok(Self::Void),
            _ => Err(format!(
                "unknown type '{s}', expected: i32, i64, u32, u64, f32, f64, string, pointer, void"
            )),
        }
    }

    pub fn to_libffi_type(&self) -> Type {
        match self {
            Self::I32 => Type::i32(),
            Self::I64 => Type::i64(),
            Self::U32 => Type::u32(),
            Self::U64 => Type::u64(),
            Self::F32 => Type::f32(),
            Self::F64 => Type::f64(),
            // strings and pointers are both just pointers at the ABI level
            Self::CString | Self::Pointer => Type::pointer(),
            Self::Void => Type::void(),
        }
    }
}

impl FfiValue {
    pub fn parse_arg(s: &str) -> Result<(FfiType, Self), String> {
        let (ty_str, val_str) = s
            .split_once(':')
            .ok_or_else(|| format!("invalid arg format '{s}', expected type:value (e.g. i32:42)"))?;

        let ty = FfiType::parse(ty_str)?;

        let val = match &ty {
            FfiType::I32 => Self::I32(
                val_str
                    .parse()
                    .map_err(|e| format!("invalid i32 value '{val_str}': {e}"))?,
            ),
            FfiType::I64 => Self::I64(
                val_str
                    .parse()
                    .map_err(|e| format!("invalid i64 value '{val_str}': {e}"))?,
            ),
            FfiType::U32 => Self::U32(
                val_str
                    .parse()
                    .map_err(|e| format!("invalid u32 value '{val_str}': {e}"))?,
            ),
            FfiType::U64 => Self::U64(
                val_str
                    .parse()
                    .map_err(|e| format!("invalid u64 value '{val_str}': {e}"))?,
            ),
            FfiType::F32 => Self::F32(
                val_str
                    .parse()
                    .map_err(|e| format!("invalid f32 value '{val_str}': {e}"))?,
            ),
            FfiType::F64 => Self::F64(
                val_str
                    .parse()
                    .map_err(|e| format!("invalid f64 value '{val_str}': {e}"))?,
            ),
            FfiType::CString => Self::CString(
                CString::new(val_str)
                    .map_err(|e| format!("invalid string value '{val_str}': {e}"))?,
            ),
            FfiType::Pointer => {
                let addr = parse_hex_or_dec(val_str)
                    .map_err(|e| format!("invalid pointer value '{val_str}': {e}"))?;
                Self::Pointer(addr as usize)
            }
            FfiType::Void => return Err("cannot use void as an argument type".to_string()),
        };

        Ok((ty, val))
    }

    pub fn to_libffi_arg(&self) -> Arg {
        match self {
            Self::I32(v) => Arg::new(v),
            Self::I64(v) => Arg::new(v),
            Self::U32(v) => Arg::new(v),
            Self::U64(v) => Arg::new(v),
            Self::F32(v) => Arg::new(v),
            Self::F64(v) => Arg::new(v),
            Self::CString(v) => Arg::new(&v.as_ptr()),
            Self::Pointer(v) => Arg::new(v),
            Self::Void => unreachable!("void cannot be an argument"),
        }
    }
}

fn parse_hex_or_dec(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}
