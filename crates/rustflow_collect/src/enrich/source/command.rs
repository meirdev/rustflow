use std::io::{self, Cursor, Read};
use std::process::{ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use process_wrap::std::{ChildWrapper, CommandWrap};

use crate::enrich::{Error, Result};

/// How often a wait looks at the limit.
const POLL: Duration = Duration::from_millis(20);

const CHUNK_SIZE: usize = 64 * 1024;

/// Chunks read ahead of the parser before the command is made to wait.
const QUEUED_CHUNKS: usize = 16;

/// Runs `command` and parses its standard output with `parse`.
///
/// Whatever was parsed counts only if the command exits successfully within
/// `timeout`: one that dies halfway leaves output that looks complete. The
/// command, along with everything it started, is killed when the time is up
/// or `cancel` is set. Its standard error is left as the collector's own.
pub fn read<T>(
    command: Command,
    timeout: Duration,
    cancel: &AtomicBool,
    parse: impl FnOnce(&mut dyn Read) -> Result<T>,
) -> Result<T> {
    let limit = Limit::new(timeout, cancel);
    let mut process = Process::spawn(command)?;
    let mut output = Output::new(process.stdout(), &limit)?;

    let parsed = parse(&mut output);
    // Read on to the end even when parsing gave up early: the exit status
    // tells a failed command from one that printed bad data.
    let status = io::copy(&mut output, &mut io::sink()).and_then(|_| process.wait(&limit))?;

    if status.success() {
        parsed
    } else {
        Err(Error::Command(status))
    }
}

struct Limit<'a> {
    timeout: Duration,
    deadline: Instant,
    cancel: &'a AtomicBool,
}

impl<'a> Limit<'a> {
    fn new(timeout: Duration, cancel: &'a AtomicBool) -> Self {
        Self {
            timeout,
            deadline: Instant::now() + timeout,
            cancel,
        }
    }

    fn check(&self) -> io::Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            Err(io::Error::other("Command cancelled"))
        } else if Instant::now() >= self.deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Command timed out after {:?}", self.timeout),
            ))
        } else {
            Ok(())
        }
    }
}

/// A child in a process group of its own, or a job on Windows. Unless it
/// exited by itself, it is killed on drop together with everything it
/// started.
struct Process {
    child: Box<dyn ChildWrapper>,
    exited: bool,
}

impl Process {
    fn spawn(mut command: Command) -> io::Result<Self> {
        command.stdin(Stdio::null()).stdout(Stdio::piped());

        let mut command = CommandWrap::from(command);
        #[cfg(unix)]
        command.wrap(process_wrap::std::ProcessGroup::leader());
        #[cfg(windows)]
        command.wrap(process_wrap::std::JobObject);

        Ok(Self {
            child: command.spawn()?,
            exited: false,
        })
    }

    fn stdout(&mut self) -> ChildStdout {
        self.child.stdout().take().expect("stdout is piped")
    }

    fn wait(&mut self, limit: &Limit) -> io::Result<ExitStatus> {
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.exited = true;
                return Ok(status);
            }
            limit.check()?;
            thread::sleep(POLL);
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Once the child is reaped its group id may name someone else's
        // group, so only a child still unreaped is killed.
        if self.exited {
            return;
        }
        let _ = self.child.start_kill();
        let _ = self.child.wait();
    }
}

/// The child's standard output, read under a limit.
///
/// A pipe read cannot be interrupted, so a thread does the reading and this
/// end waits for it only as long as the limit allows. The thread outlives a
/// timeout only if something escaped the kill and still holds the pipe; it
/// ends once that lets go.
struct Output<'a> {
    chunks: Receiver<io::Result<Vec<u8>>>,
    chunk: Cursor<Vec<u8>>,
    ended: bool,
    limit: &'a Limit<'a>,
}

impl<'a> Output<'a> {
    fn new(mut stdout: ChildStdout, limit: &'a Limit<'a>) -> io::Result<Self> {
        let (tx, chunks) = mpsc::sync_channel(QUEUED_CHUNKS);

        thread::Builder::new()
            .name("enrichment-command".into())
            .spawn(move || {
                loop {
                    let mut chunk = vec![0; CHUNK_SIZE];
                    let result = match stdout.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(len) => {
                            chunk.truncate(len);
                            Ok(chunk)
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => Err(error),
                    };
                    let failed = result.is_err();
                    if tx.send(result).is_err() || failed {
                        break;
                    }
                }
            })?;

        Ok(Self {
            chunks,
            chunk: Cursor::default(),
            ended: false,
            limit,
        })
    }
}

impl Read for Output<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let len = self.chunk.read(buf)?;
            if len > 0 || buf.is_empty() || self.ended {
                return Ok(len);
            }
            self.limit.check()?;
            match self.chunks.recv_timeout(POLL) {
                Ok(chunk) => self.chunk = Cursor::new(chunk?),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => self.ended = true,
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    fn run(script: &str, timeout: Duration, cancel: bool) -> Result<Vec<u8>> {
        read(sh(script), timeout, &AtomicBool::new(cancel), |output| {
            let mut bytes = Vec::new();
            output.read_to_end(&mut bytes)?;
            Ok(bytes)
        })
    }

    const LONG: Duration = Duration::from_secs(30);

    #[test]
    fn output_reaches_the_parser() {
        assert_eq!(
            run("printf 'a,b\\n1,2\\n'", LONG, false).unwrap(),
            b"a,b\n1,2\n"
        );
    }

    #[test]
    fn output_larger_than_the_queue_arrives_whole() {
        let bytes = run("head -c 5000000 /dev/zero", LONG, false).unwrap();
        assert_eq!(bytes.len(), 5_000_000);
    }

    #[test]
    fn failed_command_discards_its_output() {
        let error = run("printf 'a,b\\n1,2\\n'; exit 3", LONG, false).unwrap_err();
        assert!(matches!(error, Error::Command(status) if status.code() == Some(3)));
    }

    #[test]
    fn failed_command_outranks_a_parse_error() {
        let error = read(
            sh("echo partial; exit 3"),
            LONG,
            &AtomicBool::new(false),
            |_| Err::<(), _>(Error::Data("bad".into())),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Command(_)), "{error}");
    }

    #[test]
    fn parse_error_surfaces_when_the_command_succeeds() {
        // The parser stops at once; the rest must still be drained for the
        // command to finish.
        let error = read(
            sh("head -c 5000000 /dev/zero"),
            LONG,
            &AtomicBool::new(false),
            |_| Err::<(), _>(Error::Data("bad".into())),
        )
        .unwrap_err();
        assert!(matches!(error, Error::Data(_)), "{error}");
    }

    #[test]
    fn timeout_kills_the_command_and_what_it_started() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("survived");
        let script = format!("(sleep 0.5; touch '{}') & wait", marker.display());

        let error = run(&script, Duration::from_millis(100), false).unwrap_err();

        assert!(
            error.to_string().contains("timed out after 100ms"),
            "{error}"
        );
        std::thread::sleep(Duration::from_millis(800));
        assert!(!marker.exists());
    }

    #[test]
    fn timeout_covers_a_command_that_closed_its_output() {
        let error = run("exec >&-; sleep 30", Duration::from_millis(100), false).unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error}");
    }

    #[test]
    fn cancel_stops_a_running_command() {
        let started = Instant::now();
        let error = run("sleep 30", LONG, true).unwrap_err();

        assert!(error.to_string().contains("cancelled"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn missing_executable_is_an_error() {
        let result = read(
            Command::new("/nonexistent/rustflow-command"),
            LONG,
            &AtomicBool::new(false),
            |_| Ok(()),
        );
        assert!(matches!(result, Err(Error::Io(_))));
    }
}
