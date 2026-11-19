use std::fmt::{self, Write};

use jiff::Timestamp;
use jiff::tz::TimeZone;

use super::Value;
use crate::information_element::DataType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TextError {
    StructuredData,
    TimestampOutOfRange,
    Null,
    Unsupported(DataType),
    Fmt(fmt::Error),
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StructuredData => f.write_str("structured data has no textual representation"),
            Self::TimestampOutOfRange => f.write_str("timestamp out of range"),
            Self::Null => f.write_str("null value has no textual representation"),
            Self::Unsupported(data_type) => {
                write!(f, "{data_type} has no textual representation")
            }
            Self::Fmt(_) => f.write_str("formatting failed"),
        }
    }
}

impl std::error::Error for TextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fmt(e) => Some(e),
            _ => None,
        }
    }
}

impl From<fmt::Error> for TextError {
    fn from(e: fmt::Error) -> Self {
        Self::Fmt(e)
    }
}

impl Value {
    pub fn to_text(&self) -> Result<String, TextError> {
        let mut text = String::new();
        self.write_text(&mut text)?;
        Ok(text)
    }

    pub fn to_text_relative_to(&self, reference: Timestamp) -> Result<String, TextError> {
        let mut text = String::new();
        self.write_text_relative_to(&mut text, reference)?;
        Ok(text)
    }

    pub fn write_text<W: Write>(&self, w: &mut W) -> Result<(), TextError> {
        self.write_text_with(w, None)
    }

    pub fn write_text_relative_to<W: Write>(
        &self,
        w: &mut W,
        reference: Timestamp,
    ) -> Result<(), TextError> {
        self.write_text_with(w, Some(reference))
    }

    fn write_text_with<W: Write>(
        &self,
        w: &mut W,
        reference: Option<Timestamp>,
    ) -> Result<(), TextError> {
        match self {
            Value::Unsigned8(v) => write!(w, "{v}")?,
            Value::Unsigned16(v) => write!(w, "{v}")?,
            Value::Unsigned32(v) => write!(w, "{v}")?,
            Value::Unsigned64(v) => write!(w, "{v}")?,
            Value::Unsigned256(_) => return Err(TextError::Unsupported(DataType::Unsigned256)),

            Value::Signed8(v) => write!(w, "{v}")?,
            Value::Signed16(v) => write!(w, "{v}")?,
            Value::Signed32(v) => write!(w, "{v}")?,
            Value::Signed64(v) => write!(w, "{v}")?,

            Value::Float32(v) => write_float(w, *v)?,
            Value::Float64(v) => write_float(w, *v)?,

            Value::Boolean(v) => write!(w, "{v}")?,

            Value::MacAddress(octets) => write!(w, "{octets}")?,
            Value::Ipv4Address(address) => write!(w, "{address}")?,
            Value::Ipv6Address(address) => write!(w, "{address}")?,

            Value::OctetArray(bytes) => {
                bytes.iter().try_for_each(|byte| write!(w, "{byte:02x}"))?;
            }
            Value::String(v) => w.write_str(v)?,

            Value::DateTimeSeconds(_) => write_datetime(w, self.to_timestamp_with(reference), 0)?,
            Value::DateTimeMilliseconds(_) => {
                write_datetime(w, self.to_timestamp_with(reference), 3)?;
            }
            Value::DateTimeMicroseconds(_) => {
                write_datetime(w, self.to_timestamp_with(reference), 6)?;
            }
            Value::DateTimeNanoseconds(_) => {
                write_datetime(w, self.to_timestamp_with(reference), 9)?;
            }

            Value::BasicList(_) | Value::SubTemplateList(_) | Value::SubTemplateMultiList(_) => {
                return Err(TextError::StructuredData);
            }
            Value::Null => return Err(TextError::Null),
        }
        Ok(())
    }
}

fn write_datetime<W: Write>(
    w: &mut W,
    timestamp: Option<Timestamp>,
    precision: usize,
) -> Result<(), TextError> {
    // Timestamps outside Jiff's supported range are not supported.
    let timestamp = timestamp.ok_or(TextError::TimestampOutOfRange)?;

    let utc = TimeZone::UTC.to_datetime(timestamp);
    write!(w, "{utc:.precision$}")?;
    Ok(())
}

fn write_float<W, T>(w: &mut W, value: T) -> Result<(), TextError>
where
    W: Write,
    T: Copy + fmt::Display + Into<f64>,
{
    // Rust prints positive infinity as "inf" without a sign.
    if value.into() == f64::INFINITY {
        w.write_str("+inf")?;
    } else {
        write!(w, "{value}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::information_element::{DataType, ListSemantic};
    use crate::template::FieldSpecifier;
    use crate::value::{BasicList, TextError, Value};

    #[test]
    fn datetime() {
        assert_eq!(
            Value::DateTimeMilliseconds(1_700_000_000_123).to_text(),
            Ok("2023-11-14T22:13:20.123".into())
        );
    }

    #[test]
    fn booleans() {
        assert_eq!(Value::Boolean(true).to_text(), Ok("true".into()));
        assert_eq!(Value::Boolean(false).to_text(), Ok("false".into()));
    }

    #[test]
    fn addresses() {
        assert_eq!(
            Value::MacAddress([0x00, 0x1b, 0x21, 0x3c, 0x4d, 0xfe].into()).to_text(),
            Ok("00:1b:21:3c:4d:fe".into())
        );
        assert_eq!(
            Value::Ipv4Address(Ipv4Addr::new(192, 0, 2, 1)).to_text(),
            Ok("192.0.2.1".into())
        );
        assert_eq!(
            Value::Ipv6Address(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)).to_text(),
            Ok("2001:db8::1".into())
        );
    }

    #[test]
    fn bytes() {
        assert_eq!(
            Value::OctetArray(vec![0x0a, 0xff, 0x00]).to_text(),
            Ok("0aff00".into())
        );
        assert_eq!(Value::OctetArray(Vec::new()).to_text(), Ok("".into()));
    }

    #[test]
    fn datetime_past_jiff_max_is_an_error() {
        assert_eq!(
            Value::DateTimeMilliseconds(253_402_207_200_999).to_text(),
            Ok("9999-12-30T22:00:00.999".into())
        );
        assert_eq!(
            Value::DateTimeMilliseconds(253_402_207_201_000).to_text(),
            Err(TextError::TimestampOutOfRange)
        );
    }

    #[test]
    fn structured_data_and_null_are_errors() {
        assert_eq!(
            Value::BasicList(Box::new(BasicList {
                semantic: ListSemantic::Undefined,
                field: FieldSpecifier {
                    information_element_id: 8,
                    field_length: 4,
                    enterprise_number: None,
                },
                values: Vec::new(),
            }))
            .to_text(),
            Err(TextError::StructuredData)
        );
        assert_eq!(Value::Null.to_text(), Err(TextError::Null));
    }

    #[test]
    fn float_infinity() {
        assert_eq!(Value::Float64(f64::INFINITY).to_text(), Ok("+inf".into()));
        assert_eq!(Value::Float32(0.1).to_text(), Ok("0.1".into()));
    }

    #[test]
    fn unsigned256_is_unsupported() {
        assert_eq!(
            Value::Unsigned256(Box::new([0; 32])).to_text(),
            Err(TextError::Unsupported(DataType::Unsigned256))
        );
    }
}
