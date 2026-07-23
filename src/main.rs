const URL_STARLING: &str = "https://forgejo.hearthhome.lol/Saltfault/Starling.git";
const URL_TUI: &str = "https://forgejo.hearthhome.lol/Saltfault/Starling-TUI.git";
const URL_SERVER: &str = "https://forgejo.hearthhome.lol/Saltfault/Starling-Server.git";

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);

    match cmd {
        Some("install") => match args.get(2).map(String::as_str) {
            Some("tui") => install_pkg("Starling TUI", URL_TUI, install_deps_tui),
            Some("server") => install_pkg("Starling Server", URL_SERVER, install_deps_server),
            _ => {
                eprintln!("Usage: starling install <tui|server>");
                std::process::exit(1);
            }
        },
        Some("update") => match args.get(2).map(String::as_str) {
            Some("tui") => update_pkg("Starling TUI", URL_TUI, install_deps_tui),
            Some("server") => update_pkg("Starling Server", URL_SERVER, install_deps_server),
            None => {
                update_self()?;
                update_pkg("Starling TUI", URL_TUI, install_deps_tui)?;
                update_pkg("Starling Server", URL_SERVER, install_deps_server)
            }
            Some(other) => {
                eprintln!("Unknown update target: {other}");
                eprintln!("Usage: starling update [tui|server]");
                std::process::exit(1);
            }
        },

        Some("leave") => {
            let _code = args.get(2).cloned().unwrap_or_default();
            println!("To leave a flock, simply close the app (Esc).");
            println!("A roost can be stopped with: starling roost close <name>");
            Ok(())
        }
        Some("list") => {
            let roosts_dir = config_dir().join("roosts");
            if !roosts_dir.exists() {
                println!("No roosts found. Create one with: starling roost create <name>");
                return Ok(());
            }
            let mut count = 0;
            for entry in std::fs::read_dir(&roosts_dir).map_err(|e| {
                eprintln!("Error reading roosts directory: {e}");
                std::process::exit(1);
            })? {
                if let Ok(entry) = entry {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let name = entry.file_name().to_string_lossy().to_string();
                        println!("  roost: {name}");
                        count += 1;
                    }
                }
            }
            if count == 0 {
                println!("No roosts found. Create one with: starling roost create <name>");
            }
            Ok(())
        }
        Some("doctor") => {
            let cfg = config_dir();
            println!("Starling Doctor");
            println!("---------------");
            if cfg.exists() {
                println!("  ✓ config directory: {}", cfg.display());
            } else {
                println!("  ✗ config directory missing — run `starling profile`");
                return Ok(());
            }
            let identity = cfg.join("identity.key");
            if identity.exists() {
                println!("  ✓ identity key: {}", identity.display());
            } else {
                println!("  ✗ identity key missing — will be created on first launch");
            }
            let profile = cfg.join("profile.bin");
            if profile.exists() {
                println!("  ✓ profile: {}", profile.display());
            } else {
                println!("  ✗ profile not configured — run `starling profile`");
            }
            let roosts_dir = cfg.join("roosts");
            if roosts_dir.exists() {
                let count = std::fs::read_dir(&roosts_dir)
                    .map(|d| {
                        d.filter_map(|e| e.ok())
                            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                            .count()
                    })
                    .unwrap_or(0);
                println!("  ✓ roosts on disk: {count}");
                println!("    ({})", roosts_dir.display());
            } else {
                println!("  ○ no roosts directory (none created yet)");
            }
            println!();
            println!("System dependencies:");
            if std::process::Command::new("cargo").arg("--version").output().is_ok() {
                println!("  ✓ cargo installed");
            } else {
                println!("  ✗ cargo not found — install Rust: https://rustup.rs");
            }
            Ok(())
        }
        Some("logs") => {
            println!("Starling TUI logs:");
            println!("  logs/latest.log  (in the working directory)");
            Ok(())
        }
        Some("tui") => match args.get(2).map(String::as_str) {
            Some("version") => exec("starling-tui", &["--version"]),
            Some("update") => update_pkg("Starling TUI", URL_TUI, install_deps_tui),
            Some("uninstall") => uninstall_pkg("starling-tui", "Starling TUI"),
            _ => {
                eprintln!("Usage: starling tui <version|update|uninstall>");
                std::process::exit(1);
            }
        },

        Some("profile") => exec("starling-tui", &["profile"]),

        Some("open") => exec("starling-tui", &[]),
        Some("join") => {
            let code = args.get(2).cloned().unwrap_or_else(|| {
                eprintln!("Usage: starling join <code>");
                std::process::exit(1);
            });
            exec("starling-tui", &["join", &code])
        }

        Some("roost") => {
            let rest: Vec<&str> = args.iter().skip(2).map(String::as_str).collect();
            exec("starling-server", &{
                let mut v = vec!["roost"];
                v.extend(rest);
                v
            })
        }
        Some("server") => match args.get(2).map(String::as_str) {
            Some("version") => exec("starling-server", &["--version"]),
            Some("update") => update_pkg("Starling Server", URL_SERVER, install_deps_server),
            Some("uninstall") => uninstall_pkg("starling-server", "Starling Server"),
            _ => {
                eprintln!("Usage: starling server <version|update|uninstall>");
                std::process::exit(1);
            }
        },

        Some("help" | "--help" | "-h") | None => {
            print_help();
            Ok(())
        }

        Some(cmd) => {
            eprintln!("Unknown command: {cmd}");
            eprintln!("Run 'starling help' for usage.");
            std::process::exit(1);
        }
    }
}

fn exec(bin: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new(bin)
        .args(args)
        .status()
        .map_err(|e| anyhow::anyhow!("{bin} not found — run `starling install {}` first: {e}",
            if bin == "starling-tui" { "tui" } else { "server" }))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn config_dir() -> std::path::PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home).join(".config").join("starling")
    } else if let Ok(appdata) = std::env::var("APPDATA") {
        std::path::PathBuf::from(appdata).join("starling")
    } else {
        std::path::PathBuf::from(".starling")
    }
}

fn cargo_install(url: &str) -> anyhow::Result<()> {
    let status = std::process::Command::new("cargo")
        .args(["install", "--jobs", "2", "--git", url])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
    if status.success() { Ok(()) }
    else { anyhow::bail!("cargo install failed (exit code: {:?})", status.code()) }
}

fn install_pkg(name: &str, url: &str, deps: fn() -> anyhow::Result<()>) -> anyhow::Result<()> {
    deps()?;
    println!("Installing {name}...");
    cargo_install(url)?;
    println!("✓ {name} installed");
    Ok(())
}

fn update_pkg(name: &str, url: &str, deps: fn() -> anyhow::Result<()>) -> anyhow::Result<()> {
    deps()?;
    println!("Updating {name}...");
    cargo_install(url)?;
    println!("✓ {name} updated to the latest version");
    Ok(())
}

fn uninstall_pkg(bin: &str, name: &str) -> anyhow::Result<()> {
    println!("Uninstalling {name}...");
    let status = std::process::Command::new("cargo")
        .args(["uninstall", bin])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
    if status.success() {
        let cfg = config_dir();
        if cfg.exists() {
            let _ = std::fs::remove_dir_all(&cfg);
        }
        println!("✓ {name} uninstalled");
        Ok(())
    } else {
        anyhow::bail!("uninstall failed (exit code: {:?})", status.code());
    }
}

fn run_shell(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run {cmd}: {e}"))?;
    if !status.success() {
        anyhow::bail!("{cmd} failed (exit code: {:?})", status.code());
    }
    Ok(())
}

fn install_linux_deps(packages: &[&str], extra_wsl: Option<&[&str]>) -> anyhow::Result<()> {
    if std::process::Command::new("apt-get").arg("--version").output().is_ok() {
        println!("Detected Debian/Ubuntu/WSL — installing...");
        run_shell("sudo", &["apt-get", "update"])?;
        let mut apt = vec!["install", "-y"];
        apt.extend(packages);
        run_shell("sudo", &apt)?;
        if let Some(wsl_pkgs) = extra_wsl {
            if std::path::Path::new("/mnt/wslg").exists() && !std::path::Path::new("/etc/asound.conf").exists() {
                println!("Setting up WSL2 audio bridge...");
                let mut wsl = vec!["install", "-y"];
                wsl.extend(wsl_pkgs);
                run_shell("sudo", &wsl)?;
                let conf = "pcm.!default {\ntype pulse\n}\nctl.!default {\ntype pulse\n}\n";
                std::fs::write("/etc/asound.conf", conf).ok();
                println!("WSL2 audio bridge installed.");
            }
        }
    } else if std::process::Command::new("dnf").arg("--version").output().is_ok() {
        println!("Detected Fedora — installing...");
        let mut dnf = vec!["install", "-y"];
        dnf.extend(packages);
        run_shell("sudo", &["dnf", "install", "-y"])?;
    } else if std::process::Command::new("pacman").arg("--version").output().is_ok() {
        println!("Detected Arch — installing...");
        let mut pac = vec!["-S", "--noconfirm"];
        pac.extend(packages);
        run_shell("sudo", &["pacman", "-S", "--noconfirm"])?;
    } else {
        eprintln!("Could not detect a supported package manager.");
        return Err(anyhow::anyhow!("unsupported package manager"));
    }
    Ok(())
}

fn install_deps_tui() -> anyhow::Result<()> {
    if cfg!(target_os = "linux") {
        let r = install_linux_deps(
            &["build-essential", "pkg-config", "libasound2-dev", "libpulse-dev", "libclang-dev", "libv4l-dev"],
            Some(&["libasound2-plugins"]),
        );
        if let Err(e) = r {
            eprintln!("Please install manually: gcc, pkg-config, alsa-lib-dev, pulseaudio-dev, libclang-dev, libv4l-dev");
            return Err(e);
        }
    } else if cfg!(target_os = "macos") {
        if std::process::Command::new("brew").arg("--version").output().is_ok() {
            println!("Detected macOS (Homebrew) — installing...");
            run_shell("brew", &["install", "pkg-config"])?;
        } else {
            eprintln!("Please install Homebrew first: https://brew.sh");
            eprintln!("Then run: brew install pkg-config");
            std::process::exit(1);
        }
    } else if cfg!(target_os = "windows") {
        println!("On Windows, install Visual Studio Build Tools:");
        println!("  https://visualstudio.microsoft.com/visual-cpp-build-tools/");
        println!("Select 'Desktop development with C++'.");
    }
    println!("✓ TUI system dependencies installed");
    Ok(())
}

fn install_deps_server() -> anyhow::Result<()> {
    if cfg!(target_os = "linux") {
        let r = install_linux_deps(
            &["build-essential", "pkg-config", "libclang-dev"],
            None,
        );
        if let Err(e) = r {
            eprintln!("Please install manually: gcc, pkg-config, libclang-dev");
            return Err(e);
        }
    } else if cfg!(target_os = "macos") {
        if std::process::Command::new("brew").arg("--version").output().is_ok() {
            println!("Detected macOS (Homebrew) — installing...");
            run_shell("brew", &["install", "pkg-config"])?;
        } else {
            eprintln!("Please install Homebrew first: https://brew.sh");
            eprintln!("Then run: brew install pkg-config");
            std::process::exit(1);
        }
    } else if cfg!(target_os = "windows") {
        println!("On Windows, install Visual Studio Build Tools:");
        println!("  https://visualstudio.microsoft.com/visual-cpp-build-tools/");
        println!("Select 'Desktop development with C++'.");
    }
    println!("✓ Server system dependencies installed");
    Ok(())
}

fn update_self() -> anyhow::Result<()> {
    if cfg!(windows) {
        println!("Updating Starling...");
        let script = format!(
            r#"$old = "$env:USERPROFILE\.cargo\bin\starling.exe"
$bak = "$env:USERPROFILE\.cargo\bin\starling.old"
ren $old $bak 2>$null
cargo install --jobs 2 --git {URL_STARLING}
if ($LASTEXITCODE -eq 0) {{ ri $bak -ea 0; exit 0 }} else {{ ren $bak $old 2>$null; exit $LASTEXITCODE }}"#
        );
        let ps = std::env::temp_dir().join("starling-update.ps1");
        let _ = std::fs::write(&ps, script);
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&ps)
            .status()
            .map_err(|e| anyhow::anyhow!("failed to run PowerShell: {e}"))?;
        let _ = std::fs::remove_file(&ps);
        if status.success() {
            println!("✓ Starling updated to the latest version");
            Ok(())
        } else {
            eprintln!("If the update failed because starling.exe was locked,");
            eprintln!("open a new terminal and run this command directly:");
            eprintln!();
            eprintln!("  cargo install --git {URL_STARLING}");
            anyhow::bail!("update failed (exit code: {:?})", status.code());
        }
    } else {
        println!("Updating Starling...");
        cargo_install(URL_STARLING)?;
        println!("✓ Starling updated to the latest version");
        Ok(())
    }
}

fn print_help() {
    println!("Starling v{} — federated p2p communications", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage:");
    println!("  starling install tui            install the TUI client");
    println!("  starling install server         install the headless roost server");
    println!();
    println!("  starling profile                configure your profile (name, audio, identity)");
    println!("  starling join <code>            join a flock or roost");
    println!("  starling open                   open the TUI");
    println!("  starling leave <code>           leave a flock or roost");
    println!("  starling list                   list flocks and roosts on disk");
    println!("  starling doctor                 diagnose setup");
    println!("  starling logs                   show log file path");
    println!("  starling tui version            print TUI version");
    println!("  starling tui update             update the TUI");
    println!("  starling tui uninstall          uninstall the TUI");
    println!();
    println!("  starling roost create   <name>  create a new roost");
    println!("  starling roost open     <name>  start a roost (blocks)");
    println!("  starling roost close    <name>  stop a running roost");
    println!("  starling roost destroy  <name>  delete a roost and all data");
    println!("  starling roost setup    <name>  alias for create");
    println!("  starling roost invite   <name>  show invite code");
    println!("  starling roost status   <name>  show roost info");
    println!("  starling roost doctor   <name>  diagnose a roost");
    println!("  starling roost logs     <name>  show log info");
    println!("  starling roost members  <name>  list members (coming)");
    println!("  starling roost channel add <n> <ch>    add a channel (coming)");
    println!("  starling roost channel remove <n> <ch> remove a channel (coming)");
    println!("  starling server version        print Server version");
    println!("  starling server update         update the Server");
    println!("  starling server uninstall      uninstall the Server");
    println!();
    println!("  starling update                update Starling, TUI, and Server");
    println!("  starling update tui            update only the TUI");
    println!("  starling update server         update only the Server");
    println!("  starling help                  print this help");
}
