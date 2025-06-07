use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use macaddr::MacAddr6;
use primitive_types::U256;

#[derive(Debug, Clone)]
pub enum DataType {
    Unsigned8,
    Unsigned16,
    Unsigned32,
    Unsigned64,
    Unsigned256,
    Unsigned(u8),
    Signed8,
    Signed16,
    Signed32,
    Signed64,
    Signed(u8),
    Float32,
    Float64,
    Boolean,
    MacAddress,
    OctetArray,
    String,
    DateTimeSeconds,
    DateTimeMilliseconds,
    DateTimeMicroseconds,
    DateTimeNanoseconds,
    Ipv4Address,
    Ipv6Address,
    BasicList,
}

#[derive(Debug, Clone)]
pub enum DataValue {
    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned32(u32),
    Unsigned64(u64),
    Unsigned256(U256),
    Signed8(i8),
    Signed16(i16),
    Signed32(i32),
    Signed64(i64),
    Float32(f32),
    Float64(f64),
    Boolean(bool),
    MacAddress(MacAddr6),
    OctetArray(Vec<u8>),
    String(String),
    DateTimeSeconds(u32),
    DateTimeMilliseconds(u64),
    DateTimeMicroseconds(u64),
    DateTimeNanoseconds(u64),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
    BasicList(Vec<DataValue>),
}

#[derive(Debug)]
pub enum DataTypeConvertError {
    TryFromSliceError,
    FromUtf8Error,
    UndefinedError,
    UnsignedError,
    SignedError,
}

impl DataType {
    pub fn decode(&self, bytes: &[u8]) -> Result<DataValue, DataTypeConvertError> {
        match self {
            DataType::Unsigned8 => {
                let value = u8::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Unsigned8(value))
            }
            DataType::Unsigned16 => {
                let value = u16::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Unsigned16(value))
            }
            DataType::Unsigned32 => {
                let value = u32::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Unsigned32(value))
            }
            DataType::Unsigned64 => {
                let value = u64::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Unsigned64(value))
            }
            DataType::Unsigned256 => {
                let value = U256::from_big_endian(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Unsigned256(value))
            }
            DataType::Unsigned(n) => match n {
                1 => DataType::Unsigned8.decode(bytes),
                2 => DataType::Unsigned16.decode(bytes),
                4 => DataType::Unsigned32.decode(bytes),
                8 => DataType::Unsigned64.decode(bytes),
                32 => DataType::Unsigned256.decode(bytes),
                _ => Err(DataTypeConvertError::UnsignedError),
            },
            DataType::Signed(n) => match n {
                1 => DataType::Signed8.decode(bytes),
                2 => DataType::Signed16.decode(bytes),
                4 => DataType::Signed32.decode(bytes),
                8 => DataType::Signed64.decode(bytes),
                _ => Err(DataTypeConvertError::SignedError),
            },
            DataType::Signed8 => {
                let value = i8::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Signed8(value))
            }
            DataType::Signed16 => {
                let value = i16::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Signed16(value))
            }
            DataType::Signed32 => {
                let value = i32::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Signed32(value))
            }
            DataType::Signed64 => {
                let value = i64::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Signed64(value))
            }
            DataType::Float32 => {
                let value = f32::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Float32(value))
            }
            DataType::Float64 => {
                let value = f64::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::Float64(value))
            }
            DataType::Boolean => {
                let value = u8::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );

                match value {
                    1 => Ok(DataValue::Boolean(true)),
                    2 => Ok(DataValue::Boolean(false)),
                    _ => Err(DataTypeConvertError::UndefinedError),
                }
            }
            DataType::MacAddress => {
                let value: [u8; 6] = bytes
                    .try_into()
                    .or(Err(DataTypeConvertError::TryFromSliceError))?;
                let value = MacAddr6::from(value);
                Ok(DataValue::MacAddress(value))
            }
            DataType::OctetArray => {
                let value = bytes.to_vec();
                Ok(DataValue::OctetArray(value))
            }
            DataType::String => {
                let value = String::from_utf8(bytes.to_vec())
                    .or(Err(DataTypeConvertError::FromUtf8Error))?;
                Ok(DataValue::String(value))
            }
            DataType::DateTimeSeconds => {
                let value = u32::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::DateTimeSeconds(value))
            }
            DataType::DateTimeMilliseconds => {
                let value = u64::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::DateTimeMilliseconds(value))
            }
            DataType::DateTimeMicroseconds => {
                let value = u64::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::DateTimeMicroseconds(value))
            }
            DataType::DateTimeNanoseconds => {
                let value = u64::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                Ok(DataValue::DateTimeNanoseconds(value))
            }
            DataType::Ipv4Address => {
                let value: [u8; 4] = bytes
                    .try_into()
                    .or(Err(DataTypeConvertError::TryFromSliceError))?;
                let value = Ipv4Addr::from(value);
                Ok(DataValue::Ipv4Address(value))
            }
            DataType::Ipv6Address => {
                let value: [u8; 16] = bytes
                    .try_into()
                    .or(Err(DataTypeConvertError::TryFromSliceError))?;
                let value = Ipv6Addr::from(value);
                Ok(DataValue::Ipv6Address(value))
            }
            DataType::BasicList => {
                todo!();
            }
        }
    }
}

pub struct Field {
    pub name: &'static str,
    pub data_type: DataType,
}

impl Field {
    pub fn new(name: &'static str, data_type: DataType) -> Self {
        Self { name, data_type }
    }
}

pub fn default_fields() -> HashMap<u16, Field> {
    let mut fields = HashMap::new();

    fields.insert(1, Field::new("IN_BYTES", DataType::Ipv4Address));

    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_fields() {
        let fields = default_fields();

        let field = fields.get(&1).unwrap();

        println!("{:?}", field.name);

        println!("{:?}", field.data_type);

        let value = field.data_type.decode(&[1, 2, 3, 4]).unwrap();

        println!("{:#?}", value);

        // println!("{:#?}", );
    }
}
