#[cfg(unix)]
mod unix_tests {
    use std::io::Read;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn spawn_rshs() -> (std::process::Child, tempfile::TempDir) {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let serve_dir = tmpdir.path().join("serve");
        std::fs::create_dir(&serve_dir).unwrap();

        let out_file = std::fs::File::create(tmpdir.path().join("stdout.txt")).unwrap();
        let err_file = std::fs::File::create(tmpdir.path().join("stderr.txt")).unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_rshs"))
            .arg(&serve_dir)
            .arg("--port")
            .arg("0")
            .stdout(out_file)
            .stderr(err_file)
            .spawn()
            .expect("failed to spawn server");

        let stderr_path = tmpdir.path().join("stderr.txt");
        let deadline = Instant::now() + Duration::from_secs(10);

        loop {
            let mut stderr = String::new();
            if let Ok(mut f) = std::fs::File::open(&stderr_path) {
                let _ = f.read_to_string(&mut stderr);
            }
            if stderr.contains("starting HTTP server") {
                break;
            }
            if child.try_wait().unwrap().is_some() {
                panic!("server exited prematurely, stderr: {stderr}");
            }
            if Instant::now() > deadline {
                panic!("server did not start within 10s, stderr: {stderr}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        (child, tmpdir)
    }

    fn assert_graceful_shutdown(
        mut child: std::process::Child, tmpdir: tempfile::TempDir, signal_name: &str,
    ) {
        let status = child.wait().unwrap();

        let mut stderr = String::new();
        std::fs::File::open(tmpdir.path().join("stderr.txt"))
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();

        assert!(
            status.success(),
            "server exited with code: {:?}, stderr: {stderr}",
            status.code()
        );
        assert!(
            stderr.contains("shutting down gracefully"),
            "stderr should contain shutdown message for {signal_name}, got: {stderr}"
        );
    }

    #[test]
    fn test_graceful_shutdown_on_sigint() {
        let (child, tmpdir) = spawn_rshs();
        unsafe {
            libc::kill(child.id() as i32, libc::SIGINT);
        }
        assert_graceful_shutdown(child, tmpdir, "SIGINT");
    }

    #[test]
    fn test_graceful_shutdown_on_sigterm() {
        let (child, tmpdir) = spawn_rshs();
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        assert_graceful_shutdown(child, tmpdir, "SIGTERM");
    }
}
