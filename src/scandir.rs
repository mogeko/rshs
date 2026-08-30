//! Batch filesystem metadata operations via io_uring (Linux) or
//! `spawn_blocking` + `std::fs` fallback (all platforms).
//!
//! The primary entry point is [`batch_read_dir_entries`] which reads all
//! entries in a directory and collects their metadata in a single blocking
//! operation — replacing the per-entry `tokio::fs::read_dir` + `metadata`
//! serial pattern used in PROPFIND traversal.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// Linux: io_uring batch statx helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;

    /// Safe wrapper around `libc::statx` providing field accessors.
    /// Uses `libc::statx` rather than `io_uring::types::statx` because the
    /// io_uring crate's fields are private and cannot be read after completion.
    pub(super) struct StatxBuf(libc::statx);

    impl StatxBuf {
        pub(super) fn is_dir(&self) -> bool {
            (self.0.stx_mode as u32 & libc::S_IFMT) == libc::S_IFDIR
        }

        pub(super) fn size(&self) -> u64 {
            self.0.stx_size
        }

        pub(super) fn modified(&self) -> SystemTime {
            timestamp_to_systemtime(self.0.stx_mtime.tv_sec, self.0.stx_mtime.tv_nsec)
        }

        pub(super) fn created(&self) -> Option<SystemTime> {
            if self.0.stx_btime.tv_sec == 0 && self.0.stx_btime.tv_nsec == 0 {
                None
            } else {
                Some(timestamp_to_systemtime(
                    self.0.stx_btime.tv_sec,
                    self.0.stx_btime.tv_nsec,
                ))
            }
        }
    }

    fn timestamp_to_systemtime(sec: i64, nsec: u32) -> SystemTime {
        if sec >= 0 {
            SystemTime::UNIX_EPOCH + std::time::Duration::new(sec as u64, nsec)
        } else {
            SystemTime::UNIX_EPOCH - std::time::Duration::new((-sec) as u64, nsec)
        }
    }

    /// Maximum statx calls per io_uring submission.
    const BATCH_SIZE: usize = 256;

    /// Submit a batch of `statx` calls for filenames within `dir_fd` via
    /// io_uring.  Returns results indexed identically to `names`.
    /// `None` means statx failed for that entry.
    pub(super) fn batch_statx(
        dir_fd: std::os::fd::RawFd, names: &[CString],
    ) -> io::Result<Vec<Option<StatxBuf>>> {
        if names.is_empty() {
            return Ok(Vec::new());
        }

        let mut results: Vec<Option<StatxBuf>> = (0..names.len()).map(|_| None).collect();

        for chunk_start in (0..names.len()).step_by(BATCH_SIZE) {
            let chunk_end = (chunk_start + BATCH_SIZE).min(names.len());
            let chunk = &names[chunk_start..chunk_end];
            let n = chunk.len();

            let mut ring = io_uring::IoUring::new(n as u32)?;

            // Buffer uses libc::statx (readable fields).
            // io_uring::types::statx has the same #[repr(C)] kernel ABI layout —
            // the pointer cast when building the SQE is safe.
            let mut bufs: Vec<libc::statx> =
                (0..n).map(|_| unsafe { std::mem::zeroed() }).collect();

            unsafe {
                let mut sq = ring.submission();
                for (i, name) in chunk.iter().enumerate() {
                    let statx_e = io_uring::opcode::Statx::new(
                        io_uring::types::Fd(dir_fd),
                        name.as_ptr(),
                        // SAFETY: libc::statx and io_uring::types::statx share the
                        // same #[repr(C)] kernel ABI layout — the kernel writes to
                        // this memory, we read it back as libc::statx.
                        bufs.as_mut_ptr().add(i) as *mut io_uring::types::statx,
                    )
                    .mask(libc::STATX_BASIC_STATS | libc::STATX_BTIME)
                    .build()
                    .user_data(i as u64);

                    sq.push(&statx_e)
                        .map_err(|_| io::Error::other("io_uring submission queue full"))?;
                }
            }

            ring.submit_and_wait(n)?;

            for cqe in ring.completion() {
                let idx = cqe.user_data() as usize;
                if cqe.result() >= 0 && idx < n {
                    results[chunk_start + idx] = Some(StatxBuf(bufs[idx]));
                }
            }
        }

        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Metadata for a single directory entry returned by
/// [`batch_read_dir_entries`].
pub(crate) struct DirEntryMeta {
    pub name: OsString,
    pub is_dir: bool,
    pub size: u64,
    pub modified: SystemTime,
    pub created: Option<SystemTime>,
}

/// Read all entries in a directory and collect their metadata in a single
/// blocking operation dispatched through `spawn_blocking`.
///
/// On Linux, directory enumeration uses `std::fs::read_dir` and metadata is
/// collected via an io_uring batch of `statx` calls — one `io_uring_enter`
/// syscall for up to 256 entries.
///
/// On other platforms, falls back to `std::fs::read_dir` with serial
/// `std::fs::metadata()` calls — still a single `spawn_blocking`, eliminating
/// per-entry tokio scheduling overhead compared to the current
/// `tokio::fs::read_dir` + `metadata()` loop.
///
/// Entries whose metadata cannot be read are silently skipped (matching
/// the existing `continue`-on-error behaviour in the PROPFIND handlers).
///
/// # Errors
///
/// Returns an error if the directory cannot be opened for reading or
/// the `spawn_blocking` task panics.
pub(crate) async fn batch_read_dir_entries(dir_path: &Path) -> io::Result<Vec<DirEntryMeta>> {
    let path = dir_path.to_path_buf();
    tokio::task::spawn_blocking(move || batch_read_dir_entries_sync(&path))
        .await
        .map_err(io::Error::other)?
}

/// Compile-time platform dispatch.
fn batch_read_dir_entries_sync(dir_path: &Path) -> io::Result<Vec<DirEntryMeta>> {
    #[cfg(target_os = "linux")]
    {
        batch_linux(dir_path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        batch_fallback(dir_path)
    }
}

// ---------------------------------------------------------------------------
// Linux: io_uring path
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn batch_linux(dir_path: &Path) -> io::Result<Vec<DirEntryMeta>> {
    use std::os::unix::io::AsRawFd;

    // Open directory once to obtain a fd for io_uring statx (AT_EMPTY_PATH
    // is not used — we pass filenames relative to dir_fd instead).
    let dir = std::fs::File::open(dir_path)?;
    let dir_fd = dir.as_raw_fd();

    // — enumerate names (getdents64 — not batchable via io_uring) —
    let read_dir = std::fs::read_dir(dir_path)?;
    let mut names_c: Vec<CString> = Vec::new();
    let mut names_os: Vec<OsString> = Vec::new();
    let mut dtype_is_dir: Vec<Option<bool>> = Vec::new();

    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(error = %e, "skipping unreadable directory entry");
                continue;
            }
        };

        // d_type may already tell us file vs directory — record it so we
        // can skip a redundant is_dir check from statx on most filesystems.
        let ft_is_dir = entry.file_type().ok().map(|ft| ft.is_dir());

        let name = entry.file_name();
        let Ok(c_name) = CString::new(name.as_encoded_bytes()) else {
            tracing::debug!(
                name = %name.to_string_lossy(), "skipping filename with interior NUL"
            );
            continue;
        };

        names_c.push(c_name);
        names_os.push(name);
        dtype_is_dir.push(ft_is_dir);
    }

    if names_c.is_empty() {
        return Ok(Vec::new());
    }

    // — batch statx via io_uring —
    let stat_results = linux_impl::batch_statx(dir_fd, &names_c)?;
    drop(dir);

    // — merge results —
    let mut entries = Vec::with_capacity(names_c.len());
    for i in 0..names_c.len() {
        let Some(stx) = &stat_results[i] else {
            tracing::debug!(
                name = %names_os[i].to_string_lossy(), "statx failed, skipping entry"
            );
            continue;
        };

        // Prefer d_type when available (zero-cost on most filesystems);
        // fall back to statx for DT_UNKNOWN (e.g. XFS without ftype, NFS).
        let is_dir = dtype_is_dir[i].unwrap_or_else(|| stx.is_dir());

        entries.push(DirEntryMeta {
            name: names_os[i].clone(),
            is_dir,
            size: stx.size(),
            modified: stx.modified(),
            created: stx.created(),
        });
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Non-Linux fallback: std::fs in spawn_blocking
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
fn batch_fallback(dir_path: &Path) -> io::Result<Vec<DirEntryMeta>> {
    let read_dir = std::fs::read_dir(dir_path)?;
    let mut entries = Vec::new();

    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(error = %e, "skipping unreadable directory entry");
                continue;
            }
        };

        let name = entry.file_name();
        let meta = match std::fs::metadata(entry.path()) {
            Ok(m) => m,
            Err(e) => {
                let name = name.to_string_lossy();
                tracing::debug!(
                    error = %e, name = %name, "metadata failed, skipping entry"
                );
                continue;
            }
        };

        entries.push(DirEntryMeta {
            name,
            is_dir: meta.is_dir(),
            size: meta.len(),
            modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            created: meta.created().ok(),
        });
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn empty_dir_returns_empty_vec() {
        let dir = tempfile::TempDir::new().unwrap();
        let entries = batch_read_dir_entries(dir.path()).await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn files_and_subdirs_collected() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::File::create(dir.path().join("a.txt"))
            .unwrap()
            .write_all(b"hello world")
            .unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();

        let mut entries = batch_read_dir_entries(dir.path()).await.unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].name, "a.txt");
        assert!(!entries[0].is_dir);
        assert_eq!(entries[0].size, 11);

        assert_eq!(entries[1].name, "subdir");
        assert!(entries[1].is_dir);
    }

    #[tokio::test]
    async fn nonexistent_path_returns_err() {
        let result = batch_read_dir_entries(Path::new("/nonexistent/zzz")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn modified_timestamp_is_recent() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::File::create(dir.path().join("f")).unwrap();
        let before = SystemTime::now();

        let entries = batch_read_dir_entries(dir.path()).await.unwrap();
        assert_eq!(entries.len(), 1);

        let after = SystemTime::now();
        assert!(entries[0].modified <= after);
        // Allow 2 s tolerance for coarse filesystem timestamp granularity
        let tolerance = std::time::Duration::from_secs(2);
        assert!(entries[0].modified + tolerance >= before);
    }

    #[tokio::test]
    async fn large_directory_over_batch_size() {
        let dir = tempfile::TempDir::new().unwrap();
        let count = 300; // > BATCH_SIZE (256) to exercise chunked io_uring
        for i in 0..count {
            std::fs::File::create(dir.path().join(format!("file_{i:05}.txt"))).unwrap();
        }

        let entries = batch_read_dir_entries(dir.path()).await.unwrap();
        assert_eq!(entries.len(), count);
    }

    #[tokio::test]
    async fn unicode_filenames_preserved() {
        let dir = tempfile::TempDir::new().unwrap();
        let names = ["普通文件.txt", "🍕.dat", "名前.txt"];
        for name in &names {
            std::fs::File::create(dir.path().join(name)).unwrap();
        }

        let mut entries = batch_read_dir_entries(dir.path()).await.unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(entries.len(), 3);
        // OsString round-trip: names must survive the read_dir + CString + statx chain
        for entry in &entries {
            let s = entry.name.to_str().unwrap();
            assert!(names.contains(&s), "unexpected name: {s}");
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn symlink_followed_to_target() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::File::create(dir.path().join("real.txt"))
            .unwrap()
            .write_all(b"hello world")
            .unwrap();
        std::os::unix::fs::symlink(dir.path().join("real.txt"), dir.path().join("link.txt"))
            .unwrap();

        let mut entries = batch_read_dir_entries(dir.path()).await.unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(entries.len(), 2);

        let link = entries.iter().find(|e| e.name == "link.txt").unwrap();
        assert!(!link.is_dir, "symlink to file should report as a file");
        // Symlink is transparent — returns target's metadata (size 11, not the link path length)
        assert_eq!(link.size, 11, "symlink size should match target file size");
    }

    // -- Linux-only: direct io_uring path tests ------------------------

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::super::linux_impl;
        use std::os::unix::io::AsRawFd;

        /// batch_statx with empty name list returns empty result set.
        #[test]
        fn batch_statx_empty_names() {
            let dir = tempfile::TempDir::new().unwrap();
            let dir_file = std::fs::File::open(dir.path()).unwrap();
            let fd = dir_file.as_raw_fd();

            let result = linux_impl::batch_statx(fd, &[]).unwrap();
            assert!(result.is_empty());
        }

        /// batch_statx with a single file name returns one valid result.
        #[test]
        fn batch_statx_single_entry() {
            let dir = tempfile::TempDir::new().unwrap();
            std::fs::File::create(dir.path().join("f")).unwrap();
            let dir_file = std::fs::File::open(dir.path()).unwrap();
            let fd = dir_file.as_raw_fd();

            let name = std::ffi::CString::new("f").unwrap();
            let result = linux_impl::batch_statx(fd, &[name]).unwrap();

            assert_eq!(result.len(), 1);
            assert!(result[0].is_some(), "valid file should return statx data");
        }

        /// batch_statx with more entries than BATCH_SIZE splits into chunks
        /// correctly — all entries returned, none lost.
        #[test]
        fn batch_statx_chunking() {
            let dir = tempfile::TempDir::new().unwrap();
            let count = 300; // > BATCH_SIZE (256)
            for i in 0..count {
                std::fs::File::create(dir.path().join(format!("f_{i:05}"))).unwrap();
            }

            let dir_file = std::fs::File::open(dir.path()).unwrap();
            let fd = dir_file.as_raw_fd();

            let names: Vec<_> = (0..count)
                .map(|i| std::ffi::CString::new(format!("f_{i:05}")).unwrap())
                .collect();

            let result = linux_impl::batch_statx(fd, &names).unwrap();

            assert_eq!(result.len(), count);
            let success_count = result.iter().filter(|r| r.is_some()).count();
            assert_eq!(success_count, count, "all {} entries should succeed", count);
        }

        /// batch_statx with an entry that disappeared returns None for that slot.
        #[test]
        fn batch_statx_missing_entry_returns_none() {
            let dir = tempfile::TempDir::new().unwrap();
            std::fs::File::create(dir.path().join("exists")).unwrap();

            let dir_file = std::fs::File::open(dir.path()).unwrap();
            let fd = dir_file.as_raw_fd();

            let names = vec![
                std::ffi::CString::new("exists").unwrap(),
                std::ffi::CString::new("ghost").unwrap(), // never created
            ];

            let result = linux_impl::batch_statx(fd, &names).unwrap();

            assert_eq!(result.len(), 2);
            assert!(result[0].is_some(), "existing file should succeed");
            assert!(result[1].is_none(), "missing file should be None");
        }
    }
}
