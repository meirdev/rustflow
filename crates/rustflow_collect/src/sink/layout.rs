//! Reading a rotated output tree: which files are the collector's own, and
//! which of them fall in a time range.

use std::fs;
use std::ops::{Bound, RangeBounds};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Utc};

use super::destination::{LEVEL_3_MINUTES, MAX_PARTITION_DEPTH, STAMP_FORMAT, STAMP_LEN};

/// One output tree, as `--output`, `--prefix` and `--serialization`
/// describe it. Files are recognised by name alone: see [`Layout::name`].
#[derive(Clone, Debug)]
pub struct Layout {
    pub root: PathBuf,
    pub prefix: String,
    pub extension: String,
}

/// A file of the tree.
#[derive(Debug)]
pub struct Entry {
    pub path: PathBuf,
    /// Start of the window the file holds, from its name.
    pub window: DateTime<Utc>,
    /// Still being written, or left behind by a crash. Expiry removes
    /// these like any other; a reader of the tree must skip them.
    #[allow(dead_code)]
    pub temporary: bool,
}

/// The time a partition directory covers, as Unix timestamps: `start`
/// inclusive, `end` exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Period {
    pub start: i64,
    pub end: i64,
}

impl Period {
    fn overlaps(&self, range: &impl RangeBounds<i64>) -> bool {
        let after_start = match range.start_bound() {
            Bound::Included(start) => self.end > *start,
            Bound::Excluded(start) => self.end > start + 1,
            Bound::Unbounded => true,
        };
        let before_end = match range.end_bound() {
            Bound::Included(end) => self.start <= *end,
            Bound::Excluded(end) => self.start < *end,
            Bound::Unbounded => true,
        };
        after_start && before_end
    }
}

impl Layout {
    /// Every file of this tree whose window starts inside `range`,
    /// temporary files included. Partition directories outside the range
    /// are not even listed; directories that cannot be read are skipped.
    pub fn files(&self, range: impl RangeBounds<i64>) -> Vec<Entry> {
        let mut entries = Vec::new();
        self.walk(&self.root, &range, &mut |visit| {
            if let Visit::File(entry) = visit
                && range.contains(&entry.window.timestamp())
            {
                entries.push(entry);
            }
        });
        entries
    }

    /// The partition directories whose period overlaps `range`, deepest
    /// first, so each comes before the directory holding it. The root is
    /// not among them.
    pub fn dirs(&self, range: impl RangeBounds<i64>) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        self.walk(&self.root, &range, &mut |visit| {
            if let Visit::LeaveDir(path) = visit {
                dirs.push(path.to_path_buf());
            }
        });
        dirs
    }

    fn walk(&self, dir: &Path, range: &impl RangeBounds<i64>, visit: &mut impl FnMut(Visit<'_>)) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let path = entry.path();
            if kind.is_dir() {
                if let Some(period) = self.period(dir, &name)
                    && period.overlaps(range)
                {
                    self.walk(&path, range, visit);
                    visit(Visit::LeaveDir(&path));
                }
            } else if kind.is_file()
                && let Some((window, temporary)) = self.name(&name)
            {
                visit(Visit::File(Entry {
                    path,
                    window,
                    temporary,
                }));
            }
        }
    }

    /// The window in the name of a file this collector wrote, and whether
    /// the name is temporary: `<prefix>-<stamp>[-N].<extension>`, or
    /// `.<name>.<pid>.tmp` while being written.
    pub fn name(&self, name: &str) -> Option<(DateTime<Utc>, bool)> {
        let (name, temporary) = match name.strip_prefix('.').and_then(|n| n.strip_suffix(".tmp")) {
            Some(tmp) => {
                let (name, pid) = tmp.rsplit_once('.')?;
                if !is_number(pid) {
                    return None;
                }
                (name, true)
            }
            None => (name, false),
        };
        let middle = name
            .strip_prefix(self.prefix.as_str())?
            .strip_prefix('-')?
            .strip_suffix(self.extension.as_str())?
            .strip_suffix('.')?;
        let (stamp, rest) = middle.split_at_checked(STAMP_LEN)?;
        if let Some(n) = rest.strip_prefix('-') {
            if !is_number(n) {
                return None;
            }
        } else if !rest.is_empty() {
            return None;
        }
        let window = NaiveDateTime::parse_from_str(stamp, STAMP_FORMAT)
            .ok()?
            .and_utc();
        Some((window, temporary))
    }

    /// The period of partition directory `name` under `parent`, or `None`
    /// when the name is not a partition of this tree.
    pub fn period(&self, parent: &Path, name: &str) -> Option<Period> {
        let parts: Vec<u32> = parent
            .strip_prefix(&self.root)
            .ok()?
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .chain(std::iter::once(name.to_owned()))
            .enumerate()
            .map(|(depth, name)| partition_number(&name, depth))
            .collect::<Option<_>>()?;
        if parts.len() > MAX_PARTITION_DEPTH {
            return None;
        }
        let part = |i: usize, default: u32| parts.get(i).copied().unwrap_or(default);
        let year = i32::try_from(part(0, 1970)).ok()?;
        let start = Utc
            .with_ymd_and_hms(year, part(1, 1), part(2, 1), part(3, 0), part(4, 0), 0)
            .single()?;
        let end = match parts.len() {
            1 => start.with_year(start.year() + 1)?,
            2 => {
                if start.month() == 12 {
                    start.with_year(start.year() + 1)?.with_month(1)?
                } else {
                    start.with_month(start.month() + 1)?
                }
            }
            3 => start + chrono::Duration::days(1),
            4 => start + chrono::Duration::hours(1),
            _ => start + chrono::Duration::minutes(i64::from(LEVEL_3_MINUTES)),
        };
        Some(Period {
            start: start.timestamp(),
            end: end.timestamp(),
        })
    }
}

enum Visit<'a> {
    File(Entry),
    /// A partition directory, after everything in it.
    LeaveDir(&'a Path),
}

/// A partition directory is a four-digit year at the top, then a two-digit
/// month, day, hour, and finally a minute bucket.
fn partition_number(name: &str, depth: usize) -> Option<u32> {
    let width = if depth == 0 { 4 } else { 2 };
    if name.len() != width || !is_number(name) {
        return None;
    }
    let number: u32 = name.parse().ok()?;
    if depth == MAX_PARTITION_DEPTH - 1 && !number.is_multiple_of(LEVEL_3_MINUTES) {
        return None;
    }
    Some(number)
}

fn is_number(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs::File;

    use super::*;
    use crate::sink::destination::partition_path;

    pub(crate) fn stamp(s: &str) -> DateTime<Utc> {
        NaiveDateTime::parse_from_str(s, STAMP_FORMAT)
            .unwrap()
            .and_utc()
    }

    fn layout(root: &Path) -> Layout {
        Layout {
            root: root.to_path_buf(),
            prefix: "flows".into(),
            extension: "parquet".into(),
        }
    }

    #[test]
    fn names_of_own_files_carry_their_window() {
        let layout = layout(Path::new("/out"));
        let name = |name: &str| layout.name(name).map(|(w, tmp)| (w.timestamp(), tmp));
        let t = stamp("20260820T120000Z").timestamp();

        assert_eq!(name("flows-20260820T120000Z.parquet"), Some((t, false)));
        assert_eq!(name("flows-20260820T120000Z-3.parquet"), Some((t, false)));
        assert_eq!(
            name(".flows-20260820T120000Z.parquet.4242.tmp"),
            Some((t, true))
        );
        assert_eq!(
            name(".flows-20260820T120000Z-1.parquet.4242.tmp"),
            Some((t, true))
        );

        assert_eq!(name("flows-20260820T120000Z.ndjson"), None);
        assert_eq!(name("netflow-20260820T120000Z.parquet"), None);
        assert_eq!(name("flows-20260820T120000Z-x.parquet"), None);
        assert_eq!(name("flows-20260820T120000Z-.parquet"), None);
        assert_eq!(name("flows-2026082T120000Z.parquet"), None);
        assert_eq!(name("flows-20261320T120000Z.parquet"), None);
        assert_eq!(name(".flows-20260820T120000Z.parquet.tmp"), None);
        assert_eq!(name(".flows-20260820T120000Z.parquet.pid.tmp"), None);
        assert_eq!(name("notes.txt"), None);
        assert_eq!(name("flows-"), None);
    }

    #[test]
    fn partition_periods_follow_the_layout() {
        let root = Path::new("/out");
        let layout = layout(root);
        let period =
            |parent: &Path, name: &str| layout.period(parent, name).map(|p| (p.start, p.end));
        let at = |s: &str| stamp(s).timestamp();

        assert_eq!(
            period(root, "2026"),
            Some((at("20260101T000000Z"), at("20270101T000000Z")))
        );
        assert_eq!(
            period(&root.join("2026"), "12"),
            Some((at("20261201T000000Z"), at("20270101T000000Z")))
        );
        assert_eq!(
            period(&root.join("2026/08"), "20"),
            Some((at("20260820T000000Z"), at("20260821T000000Z")))
        );
        assert_eq!(
            period(&root.join("2026/08/20"), "12"),
            Some((at("20260820T120000Z"), at("20260820T130000Z")))
        );
        assert_eq!(
            period(&root.join("2026/08/20/12"), "35"),
            Some((at("20260820T123500Z"), at("20260820T124000Z")))
        );

        assert_eq!(period(root, "archive"), None);
        assert_eq!(period(root, "26"), None);
        assert_eq!(period(&root.join("2026"), "2026"), None);
        assert_eq!(period(&root.join("2026"), "13"), None);
        assert_eq!(period(&root.join("2026/08/20/12"), "37"), None);
        assert_eq!(period(&root.join("2026/08/20/12/35"), "00"), None);
    }

    #[test]
    fn files_in_a_range_skip_partitions_outside_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let layout = layout(root);
        let touch = |path: PathBuf| {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            File::create(&path).unwrap();
            path
        };
        let own = |level: u8, s: &str| partition_path(root, level, "flows", "parquet", stamp(s));

        let before = touch(own(2, "20260820T115500Z"));
        let first = touch(own(2, "20260820T120000Z"));
        let flat = touch(own(0, "20260820T121000Z"));
        let tmp = touch(root.join(".flows-20260820T122000Z.parquet.7.tmp"));
        let last = touch(own(3, "20260820T125500Z"));
        let after = touch(own(2, "20260820T130000Z"));
        // Misfiled under a later hour: never listed for this range, since
        // that directory is not opened.
        touch(root.join("2026/08/20/14/flows-20260820T121500Z.parquet"));
        touch(root.join("2026/08/20/12/other-20260820T121500Z.parquet"));
        touch(root.join("archive/flows-20260820T121500Z.parquet"));

        let range = stamp("20260820T120000Z").timestamp()..stamp("20260820T130000Z").timestamp();
        let mut entries = layout.files(range);
        entries.sort_by_key(|e| e.window);

        let listed: Vec<_> = entries.iter().map(|e| e.path.clone()).collect();
        assert_eq!(listed, [first, flat, tmp.clone(), last]);
        assert_eq!(
            entries.iter().map(|e| e.temporary).collect::<Vec<_>>(),
            [false, false, true, false]
        );
        assert!(before.exists() && after.exists());

        assert_eq!(layout.files(..).len(), 7);
    }

    #[test]
    fn dirs_in_a_range_come_deepest_first() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let layout = layout(root);
        fs::create_dir_all(root.join("2026/08/19/23")).unwrap();
        fs::create_dir_all(root.join("2026/08/20/11")).unwrap();
        fs::create_dir_all(root.join("2026/08/20/12")).unwrap();
        fs::create_dir_all(root.join("archive")).unwrap();

        let dirs = layout.dirs(..stamp("20260820T120000Z").timestamp());

        let relative: Vec<_> = dirs
            .iter()
            .map(|d| d.strip_prefix(root).unwrap().to_str().unwrap())
            .collect();
        assert!(!relative.contains(&"2026/08/20/12"), "{relative:?}");
        assert!(!relative.contains(&"archive"), "{relative:?}");
        for dir in [
            "2026/08/19/23",
            "2026/08/19",
            "2026/08/20/11",
            "2026/08/20",
            "2026/08",
            "2026",
        ] {
            assert!(relative.contains(&dir), "{dir} missing from {relative:?}");
        }
        let position = |d: &str| relative.iter().position(|r| *r == d).unwrap();
        assert!(position("2026/08/19/23") < position("2026/08/19"));
        assert!(position("2026/08/19") < position("2026/08"));
        assert!(position("2026/08/20/11") < position("2026/08/20"));
        assert!(position("2026/08") < position("2026"));
    }
}
