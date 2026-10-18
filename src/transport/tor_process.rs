use std::{
    env, fs, io,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub struct TorProcess {
    child: Child,
    runtime_dir: PathBuf,
    control_addr: SocketAddr,
    socks_addr: SocketAddr,
    cookie_path: PathBuf,
    log_path: PathBuf,
}

impl TorProcess {
    pub fn start() -> io::Result<Self> {
        let executable = Self::find_tor_executable()?;
        let support_dir = executable
            .parent()
            .ok_or_else(|| io::Error::other("Diretorio do Tor invalido"))?
            .to_path_buf();

        let runtime_dir = Self::create_runtime_dir()?;
        let cookie_path = runtime_dir.join("control_auth_cookie");
        let log_path = runtime_dir.join("tor.log");
        let data_dir = runtime_dir.join("data");

        fs::create_dir_all(&data_dir)?;

        let socks_addr = Self::reserve_local_addr()?;
        let control_addr = Self::reserve_local_addr()?;

        let config_path = runtime_dir.join("torrc");
        let config = format!(
            concat!(
                "DataDirectory {}\n",
                "SocksPort {}\n",
                "ControlPort {}\n",
                "CookieAuthentication 1\n",
                "CookieAuthFile {}\n",
                "AvoidDiskWrites 1\n",
                "Log notice file {}\n"
            ),
            data_dir.display(),
            socks_addr,
            control_addr,
            cookie_path.display(),
            log_path.display(),
        );

        fs::write(&config_path, config)?;

        let mut command = Command::new(&executable);
        command
            .arg("-f")
            .arg(&config_path)
            .arg("--defaults-torrc")
            .arg("/dev/null")
            .current_dir(&runtime_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        // Tor empacotado pode precisar das bibliotecas distribuídas junto dele.
        let library_dir = support_dir.join("lib");
        if library_dir.is_dir() {
            command.env("LD_LIBRARY_PATH", library_dir);
        }

        let child = command.spawn()?;

        Ok(Self {
            child,
            runtime_dir,
            control_addr,
            socks_addr,
            cookie_path,
            log_path,
        })
    }

    fn find_tor_executable() -> io::Result<PathBuf> {
        let candidates = [
            PathBuf::from("support-files/tor-linux-x86_64-15.0.25/tor/tor"),
            PathBuf::from("../support-files/tor-linux-x86_64-15.0.25/tor/tor"),
        ];

        for candidate in candidates {
            if candidate.is_file() {
                return fs::canonicalize(candidate);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Executavel Tor nao encontrado em support-files",
        ))
    }

    fn create_runtime_dir() -> io::Result<PathBuf> {
        let base = env::temp_dir();

        for attempt in 0..100 {
            let path = base.join(format!("cryptand-tor-{}-{attempt}", std::process::id()));

            match fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                    }

                    return Ok(path);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Nao foi possivel criar diretorio temporario exclusivo",
        ))
    }

    fn reserve_local_addr() -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.local_addr()
    }

    pub fn wait_for_bootstrap(&mut self, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;

        loop {
            if self.child.try_wait()?.is_some() {
                let log = fs::read_to_string(&self.log_path).unwrap_or_default();
                return Err(io::Error::other(format!(
                    "Tor encerrou antes do bootstrap. Log: {}\n{}",
                    self.log_path.display(),
                    log
                )));
            }

            let log = fs::read_to_string(&self.log_path).unwrap_or_default();

            if log.contains("Bootstrapped 100%") {
                return Ok(());
            }

            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "Tor nao concluiu o bootstrap. Consulte: {}",
                        self.log_path.display()
                    ),
                ));
            }

            thread::sleep(Duration::from_millis(250));
        }
    }

    pub fn control_addr(&self) -> SocketAddr {
        self.control_addr
    }

    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    pub fn cookie_path(&self) -> &Path {
        &self.cookie_path
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    pub fn is_running(&mut self) -> io::Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        match self.child.try_wait()? {
            Some(_) => {}
            None => {
                self.child.kill()?;
                self.child.wait()?;
            }
        }

        Ok(())
    }
}

impl Drop for TorProcess {
    fn drop(&mut self) {
        let _ = self.shutdown();
        let _ = fs::remove_dir_all(&self.runtime_dir);
    }
}
