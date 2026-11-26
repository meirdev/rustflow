use std::{error, fmt};

use winnow::error::{ContextError, StrContext, StrContextValue};

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError(pub(crate) ContextError);

impl ParseError {
    pub fn label(&self) -> Option<&'static str> {
        self.0.context().find_map(|context| match context {
            StrContext::Label(label) => Some(*label),
            _ => None,
        })
    }

    pub fn expected(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.context().filter_map(|context| match context {
            StrContext::Expected(
                StrContextValue::Description(text) | StrContextValue::StringLiteral(text),
            ) => Some(*text),
            _ => None,
        })
    }

    pub(crate) fn write_message(
        &self,
        f: &mut fmt::Formatter<'_>,
        packet: impl fmt::Display,
    ) -> fmt::Result {
        write!(f, "the {packet} does not parse")?;
        let mut separator = ": ";
        if let Some(label) = self.label() {
            write!(f, "{separator}invalid {label}")?;
            separator = "; ";
        }
        for (i, expected) in self.expected().enumerate() {
            match i {
                0 => write!(f, "{separator}expected {expected}")?,
                _ => write!(f, ", {expected}")?,
            }
        }
        Ok(())
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_message(f, "packet")
    }
}

impl error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.0.cause().map(|cause| cause as _)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use crate::reader::{NetflowProcessor, Processor, ReadError};

    #[test]
    fn says_what_is_malformed() {
        let mut packet = vec![0, 9, 0, 1];
        packet.extend([0; 16]);
        // A flow set shorter than its own header.
        packet.extend([0, 0, 0, 2]);

        let read_error = NetflowProcessor::default()
            .parse(Ipv4Addr::LOCALHOST.into(), &packet, Instant::now())
            .unwrap_err();
        assert_eq!(
            read_error.to_string(),
            "the NETFLOW_V9 packet does not parse: invalid flow set length; \
             expected at least the 4-octet flow set header"
        );

        let ReadError::Parse { error, .. } = read_error else {
            panic!("{read_error:?}");
        };
        assert_eq!(error.label(), Some("flow set length"));
        assert_eq!(
            error.expected().collect::<Vec<_>>(),
            ["at least the 4-octet flow set header"]
        );
        assert_eq!(
            error.to_string(),
            "the packet does not parse: invalid flow set length; \
             expected at least the 4-octet flow set header"
        );
    }
}
