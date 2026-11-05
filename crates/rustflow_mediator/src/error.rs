use std::{error, fmt};

/// Why a configuration could not become a pipeline.
#[derive(Debug)]
pub enum Error {
    Parse(toml::de::Error),
    /// Every pipeline gets its records from somewhere.
    NoSources,
    /// Every pipeline exports somewhere.
    NoExporters,
    UnknownMeter(String),
    UnknownProcess(String),
    UnknownExporter(String),
    /// A component's constructor rejected its options.
    Component {
        name: String,
        source: Box<dyn error::Error + Send + Sync>,
    },
    /// A source, process or exporter name given to more than one of them.
    DuplicateName(String),
    /// A component with no inputs would never receive anything.
    NoInputs(String),
    /// An input naming no source and no process.
    UnknownInput {
        component: String,
        input: String,
    },
    /// A process among its own inputs' inputs.
    Cycle(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "{e}"),
            Self::NoSources => f.write_str("the pipeline has no collector or meter"),
            Self::NoExporters => f.write_str("the pipeline has no exporter"),
            Self::UnknownMeter(kind) => write!(f, "unknown meter type '{kind}'"),
            Self::UnknownProcess(kind) => write!(f, "unknown process type '{kind}'"),
            Self::UnknownExporter(kind) => write!(f, "unknown exporter type '{kind}'"),
            Self::Component { name, source } => write!(f, "{name}: {source}"),
            Self::DuplicateName(name) => write!(f, "the name '{name}' is used twice"),
            Self::NoInputs(name) => write!(f, "{name}: no inputs"),
            Self::UnknownInput { component, input } => {
                write!(f, "{component}: unknown input '{input}'")
            }
            Self::Cycle(name) => write!(f, "{name} is fed by itself, through its inputs"),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Parse(e) => Some(e),
            Self::Component { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}
