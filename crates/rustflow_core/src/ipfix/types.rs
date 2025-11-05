use std::fmt::{self, Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use macaddr::MacAddr6;
use primitive_types::U256;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum UserDefindDataType {
    Unsigned,
    Signed,
    Float,
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
    SubTemplateList,
    SubTemplateMultiList,
}

impl From<&str> for UserDefindDataType {
    fn from(value: &str) -> Self {
        match value {
            "unsigned" => UserDefindDataType::Unsigned,
            "signed" => UserDefindDataType::Signed,
            "float" => UserDefindDataType::Float,
            "boolean" => UserDefindDataType::Boolean,
            "macAddress" => UserDefindDataType::MacAddress,
            "octetArray" => UserDefindDataType::OctetArray,
            "string" => UserDefindDataType::String,
            "dateTimeSeconds" => UserDefindDataType::DateTimeSeconds,
            "dateTimeMilliseconds" => UserDefindDataType::DateTimeMilliseconds,
            "dateTimeMicroseconds" => UserDefindDataType::DateTimeMicroseconds,
            "dateTimeNanoseconds" => UserDefindDataType::DateTimeNanoseconds,
            "ipv4Address" => UserDefindDataType::Ipv4Address,
            "ipv6Address" => UserDefindDataType::Ipv6Address,
            "basicList" => UserDefindDataType::BasicList,
            "subTemplateList" => UserDefindDataType::SubTemplateList,
            "subTemplateMultiList" => UserDefindDataType::SubTemplateMultiList,
            _ => panic!("Unknown user defined data type: {}", value),
        }
    }
}

impl UserDefindDataType {
    pub fn to_data_type(&self, length: u16) -> DataType {
        match self {
            UserDefindDataType::Unsigned => DataType::Unsigned(length),
            UserDefindDataType::Signed => DataType::Signed(length),
            UserDefindDataType::Float => DataType::Float(length),
            UserDefindDataType::Boolean => DataType::Boolean,
            UserDefindDataType::MacAddress => DataType::MacAddress,
            UserDefindDataType::OctetArray => DataType::OctetArray,
            UserDefindDataType::String => DataType::String,
            UserDefindDataType::DateTimeSeconds => DataType::DateTimeSeconds,
            UserDefindDataType::DateTimeMilliseconds => DataType::DateTimeMilliseconds,
            UserDefindDataType::DateTimeMicroseconds => DataType::DateTimeMicroseconds,
            UserDefindDataType::DateTimeNanoseconds => DataType::DateTimeNanoseconds,
            UserDefindDataType::Ipv4Address => DataType::Ipv4Address,
            UserDefindDataType::Ipv6Address => DataType::Ipv6Address,
            UserDefindDataType::BasicList => DataType::BasicList,
            UserDefindDataType::SubTemplateList => DataType::SubTemplateList,
            UserDefindDataType::SubTemplateMultiList => DataType::SubTemplateMultiList,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Serialize)]
pub enum StructuredDataSemantic {
    NoneOf = 0x00,
    ExactlyOneOf = 0x01,
    OneOrMoreOf = 0x02,
    AllOf = 0x03,
    Ordered = 0x04,
    Undefined = 0xff,
}

impl From<u8> for StructuredDataSemantic {
    fn from(value: u8) -> Self {
        match value {
            0x00 => StructuredDataSemantic::NoneOf,
            0x01 => StructuredDataSemantic::ExactlyOneOf,
            0x02 => StructuredDataSemantic::OneOrMoreOf,
            0x03 => StructuredDataSemantic::AllOf,
            0x04 => StructuredDataSemantic::Ordered,
            0xff => StructuredDataSemantic::Undefined,
            _ => todo!(),
        }
    }
}

impl Display for StructuredDataSemantic {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            StructuredDataSemantic::NoneOf => write!(f, "noneOf"),
            StructuredDataSemantic::ExactlyOneOf => write!(f, "exactlyOneOf"),
            StructuredDataSemantic::OneOrMoreOf => write!(f, "oneOrMoreOf"),
            StructuredDataSemantic::AllOf => write!(f, "allOf"),
            StructuredDataSemantic::Ordered => write!(f, "ordered"),
            StructuredDataSemantic::Undefined => write!(f, "undefined"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum DataType {
    Unsigned8,
    Unsigned16,
    Unsigned32,
    Unsigned64,
    Unsigned256,
    Unsigned(u16),
    Signed8,
    Signed16,
    Signed32,
    Signed64,
    Signed(u16),
    Float32,
    Float64,
    Float(u16),
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
    SubTemplateList,
    SubTemplateMultiList,
}

#[derive(Debug, Clone, Serialize)]
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
    DateTimeSeconds(chrono::DateTime<Utc>),
    DateTimeMilliseconds(chrono::DateTime<Utc>),
    DateTimeMicroseconds(chrono::DateTime<Utc>),
    DateTimeNanoseconds(chrono::DateTime<Utc>),
    Ipv4Address(Ipv4Addr),
    Ipv6Address(Ipv6Addr),
    BasicList(Vec<DataValue>),
    Null,
}

impl DataType {
    pub fn is_ipv4_address(&self) -> bool {
        matches!(self, DataType::Ipv4Address)
    }

    pub fn is_ipv6_address(&self) -> bool {
        matches!(self, DataType::Ipv6Address)
    }

    pub fn is_mac_address(&self) -> bool {
        matches!(self, DataType::MacAddress)
    }

    pub fn is_octet_array(&self) -> bool {
        matches!(self, DataType::OctetArray)
    }

    pub fn is_string(&self) -> bool {
        matches!(self, DataType::String)
    }

    pub fn is_boolean(&self) -> bool {
        matches!(self, DataType::Boolean)
    }

    pub fn is_date_time(&self) -> bool {
        matches!(
            self,
            DataType::DateTimeSeconds
                | DataType::DateTimeMilliseconds
                | DataType::DateTimeMicroseconds
                | DataType::DateTimeNanoseconds
        )
    }

    pub fn is_basic_list(&self) -> bool {
        matches!(self, DataType::BasicList)
    }

    pub fn is_sub_template_list(&self) -> bool {
        matches!(self, DataType::SubTemplateList)
    }

    pub fn is_sub_template_multi_list(&self) -> bool {
        matches!(self, DataType::SubTemplateMultiList)
    }

    pub fn is_unsigned(&self) -> bool {
        matches!(
            self,
            DataType::Unsigned8
                | DataType::Unsigned16
                | DataType::Unsigned32
                | DataType::Unsigned64
                | DataType::Unsigned256
                | DataType::Unsigned(_)
        )
    }

    pub fn is_signed(&self) -> bool {
        matches!(
            self,
            DataType::Signed8
                | DataType::Signed16
                | DataType::Signed32
                | DataType::Signed64
                | DataType::Signed(_)
        )
    }
}

impl Display for DataValue {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            DataValue::Unsigned8(v) => write!(f, "{}", v),
            DataValue::Unsigned16(v) => write!(f, "{}", v),
            DataValue::Unsigned32(v) => write!(f, "{}", v),
            DataValue::Unsigned64(v) => write!(f, "{}", v),
            DataValue::Unsigned256(v) => write!(f, "{}", v),
            DataValue::Signed8(v) => write!(f, "{}", v),
            DataValue::Signed16(v) => write!(f, "{}", v),
            DataValue::Signed32(v) => write!(f, "{}", v),
            DataValue::Signed64(v) => write!(f, "{}", v),
            DataValue::Float32(v) => write!(f, "{}", v),
            DataValue::Float64(v) => write!(f, "{}", v),
            DataValue::Boolean(v) => write!(f, "{}", v),
            DataValue::MacAddress(v) => write!(f, "{}", v),
            DataValue::OctetArray(v) => write!(f, "{}", hex::encode(v)),
            DataValue::String(v) => write!(f, "{}", v),
            DataValue::DateTimeSeconds(v) => write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S")),
            DataValue::DateTimeMilliseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%3f"))
            }
            DataValue::DateTimeMicroseconds(v) => {
                write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%6f"))
            }
            DataValue::DateTimeNanoseconds(v) => write!(f, "{}", v.format("%Y-%m-%dT%H:%M:%S.%9f")),
            DataValue::Ipv4Address(v) => write!(f, "{}", v),
            DataValue::Ipv6Address(v) => write!(f, "{}", v),
            DataValue::BasicList(v) => write!(f, "{:?}", v),
            DataValue::Null => write!(f, ""),
        }
    }
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
            DataType::Float(n) => match n {
                4 => DataType::Float32.decode(bytes),
                8 => DataType::Float64.decode(bytes),
                _ => Err(DataTypeConvertError::UndefinedError),
            },
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
                let value = DateTime::<Utc>::from_timestamp(value as i64, 0)
                    .ok_or(DataTypeConvertError::UndefinedError)?;
                Ok(DataValue::DateTimeSeconds(value))
            }
            DataType::DateTimeMilliseconds => {
                let value = u64::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                let value = DateTime::<Utc>::from_timestamp_millis(value as i64)
                    .ok_or(DataTypeConvertError::UndefinedError)?;
                Ok(DataValue::DateTimeMilliseconds(value))
            }
            DataType::DateTimeMicroseconds => {
                let value = u64::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                let value = DateTime::<Utc>::from_timestamp_micros(value as i64)
                    .ok_or(DataTypeConvertError::UndefinedError)?;
                Ok(DataValue::DateTimeMicroseconds(value))
            }
            DataType::DateTimeNanoseconds => {
                let value = u64::from_be_bytes(
                    bytes
                        .try_into()
                        .or(Err(DataTypeConvertError::TryFromSliceError))?,
                );
                let value = DateTime::<Utc>::from_timestamp_nanos(value as i64);
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
            DataType::SubTemplateList => {
                todo!();
            }
            DataType::SubTemplateMultiList => {
                todo!();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc7373() {
        let data_value = DataValue::String("hello".to_string());
        assert_eq!(data_value.to_string(), "hello");

        let data_value = DataValue::Unsigned8(12);
        assert_eq!(data_value.to_string(), "12");

        let data_value = DataValue::Unsigned16(12345);
        assert_eq!(data_value.to_string(), "12345");

        let data_value = DataValue::Unsigned32(1234567);
        assert_eq!(data_value.to_string(), "1234567");

        let data_value = DataValue::Unsigned64(123456789);
        assert_eq!(data_value.to_string(), "123456789");

        let data_value = DataValue::Ipv4Address(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(data_value.to_string(), "192.168.1.1");

        let data_value = DataValue::Ipv6Address(Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        ));
        assert_eq!(data_value.to_string(), "2001:db8:85a3::8a2e:370:7334");

        let data_value = DataValue::MacAddress(MacAddr6::new(0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e));
        assert_eq!(data_value.to_string(), "00:1A:2B:3C:4D:5E");

        let data_value = DataValue::Boolean(false);
        assert_eq!(data_value.to_string(), "false");

        let data_value = DataValue::Boolean(true);
        assert_eq!(data_value.to_string(), "true");

        let data_value = DataValue::Signed8(-12);
        assert_eq!(data_value.to_string(), "-12");

        let data_value = DataValue::Signed16(-12345);
        assert_eq!(data_value.to_string(), "-12345");

        let data_value = DataValue::Signed32(-1234567);
        assert_eq!(data_value.to_string(), "-1234567");

        let data_value = DataValue::Signed64(-123456789);
        assert_eq!(data_value.to_string(), "-123456789");

        let data_value = DataValue::Float32(3.14);
        assert_eq!(data_value.to_string(), "3.14");

        let data_value = DataValue::Float64(3.1415);
        assert_eq!(data_value.to_string(), "3.1415");

        let data_value = DataValue::Float32(f32::NAN);
        assert!(data_value.to_string().contains("NaN"));

        let data_value = DataValue::Float64(f64::INFINITY);
        assert!(data_value.to_string().contains("inf"));

        let data_value = DataValue::Float64(f64::NEG_INFINITY);
        assert!(data_value.to_string().contains("-inf"));

        let data_value = DataValue::OctetArray(vec![1, 2, 3, 4]);
        assert_eq!(data_value.to_string(), "01020304");

        let data_value =
            DataValue::DateTimeSeconds(DateTime::<Utc>::from_timestamp(1757598559, 0).unwrap());
        assert_eq!(data_value.to_string(), "2025-09-11T13:49:19");

        let data_value = DataValue::DateTimeMilliseconds(
            DateTime::<Utc>::from_timestamp_millis(1757598559000).unwrap(),
        );
        assert_eq!(data_value.to_string(), "2025-09-11T13:49:19.000");

        let data_value = DataValue::DateTimeMicroseconds(
            DateTime::<Utc>::from_timestamp_micros(1757598559000000).unwrap(),
        );
        assert_eq!(data_value.to_string(), "2025-09-11T13:49:19.000000");

        let data_value = DataValue::DateTimeNanoseconds(DateTime::<Utc>::from_timestamp_nanos(
            1757598559000000000,
        ));
        assert_eq!(data_value.to_string(), "2025-09-11T13:49:19.000000000");
    }
}
