use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sampling {
    /// Systematic count-based: 1 out of every `interval` packets.
    Count { interval: u32 },
}

impl fmt::Display for Sampling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count { interval } => write!(f, "1 out of {interval} packets"),
        }
    }
}

pub enum Sampler {
    Count { interval: u32, countdown: u32 },
}

impl Sampler {
    pub fn new(sampling: Sampling) -> Self {
        match sampling {
            Sampling::Count { interval } => Self::Count {
                interval: interval.max(1),
                countdown: 1,
            },
        }
    }

    pub fn select(&mut self) -> bool {
        match self {
            Self::Count {
                interval,
                countdown,
            } => {
                if *countdown > 1 {
                    *countdown -= 1;
                    false
                } else {
                    *countdown = *interval;
                    true
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_selects_one_in_n() {
        let mut sampler = Sampler::new(Sampling::Count { interval: 10 });
        assert_eq!((0..1_000).filter(|_| sampler.select()).count(), 100);
    }

    #[test]
    fn count_of_zero_selects_everything() {
        let mut sampler = Sampler::new(Sampling::Count { interval: 0 });
        assert!((0..10).all(|_| sampler.select()));
    }
}
