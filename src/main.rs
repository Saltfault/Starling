fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);

    match cmd {
        // ── Installer ────────────────────────────────────────────────
        Some("install") => match args.get(2).map(String::as_str) {
            Some("tui") => install_tui(),
            Some("server") => install_server(),
            _ => {
                eprintln!("Usage: starling install <tui|server>");
                std::process::exit(1);
            }
        },
        Some("update") => match args.get(2).map(String::as_str) {
            Some("tui") => update_tui(),
            Some("server") => update_server(),
            None => {
                update_self()?;
                update_tui()?;
                update_server()
            }
            Some(other) => {
                eprintln!("Unknown update target: {other}");
                eprintln!("Usage: starling update [tui|server]");
                std::process::exit(1);
            }
        },

        // ── System dependencies ──────────────────────────────────────
        Some("setup") => match args.get(2).map(String::as_str) {
            Some("tui") => install_deps_tui(),
            Some("server") => install_deps_server(),
            _ => {
                eprintln!("Usage: starling setup <tui|server>");
                std::process::exit(1);
            }
        },

        // ── TUI commands (handled directly) ──────────────────────────
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
            Some("update") => update_tui(),
            Some("uninstall") => {
                println!("Uninstalling Starling TUI...");
                let status = std::process::Command::new("cargo")
                    .args(["uninstall", "starling-tui"])
                    .status()
                    .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
                if status.success() {
                    let cfg = config_dir();
                    if cfg.exists() {
                        let _ = std::fs::remove_dir_all(&cfg);
                    }
                    println!("✓ Starling TUI uninstalled");
                } else {
                    anyhow::bail!("uninstall failed (exit code: {:?})", status.code());
                }
                Ok(())
            }
            _ => {
                eprintln!("Usage: starling tui <version|update|uninstall>");
                std::process::exit(1);
            }
        },

        // ── Profile wizard (forwarded to starling-tui) ──────────────
        Some("profile") => exec("starling-tui", &["profile"]),

        // ── TUI commands (forwarded to starling-tui) ─────────────────
        Some("open") => exec("starling-tui", &[]),
        Some("join") => {
            let code = args.get(2).cloned().unwrap_or_else(|| {
                eprintln!("Usage: starling join <code>");
                std::process::exit(1);
            });
            exec("starling-tui", &["join", &code])
        }

        // ── Server commands (forwarded to starling-server) ───────────
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
            Some("update") => update_server(),
            Some("uninstall") => {
                println!("Uninstalling Starling Server...");
                let status = std::process::Command::new("cargo")
                    .args(["uninstall", "starling-server"])
                    .status()
                    .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
                if status.success() {
                    let cfg = config_dir();
                    if cfg.exists() {
                        let _ = std::fs::remove_dir_all(&cfg);
                    }
                    println!("✓ Starling Server uninstalled");
                } else {
                    anyhow::bail!("uninstall failed (exit code: {:?})", status.code());
                }
                Ok(())
            }
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

fn install_tui() -> anyhow::Result<()> {
    println!("Installing Starling TUI...");
    let status = std::process::Command::new("cargo")
        .args(["install", "--git", "https://forgejo.hearthhome.lol/Saltfault/Starling-TUI.git"])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
    if status.success() {
        println!("✓ Starling TUI installed");
        Ok(())
    } else {
        anyhow::bail!("install failed (exit code: {:?})", status.code());
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

fn install_deps_tui() -> anyhow::Result<()> {
    if cfg!(target_os = "linux") {
        if std::process::Command::new("apt-get").arg("--version").output().is_ok() {
            println!("Detected Debian/Ubuntu/WSL — installing...");
            run_shell("sudo", &["apt-get", "update"])?;
            run_shell("sudo", &["apt-get", "install", "-y",
                "build-essential", "pkg-config", "libasound2-dev",
                "libpulse-dev", "libclang-dev", "libv4l-dev"])?;
            if std::path::Path::new("/mnt/wslg").exists() && !std::path::Path::new("/etc/asound.conf").exists() {
                println!("Setting up WSL2 audio bridge...");
                run_shell("sudo", &["apt-get", "install", "-y", "libasound2-plugins"])?;
                let conf = "pcm.!default {\ntype pulse\n}\nctl.!default {\ntype pulse\n}\n";
                std::fs::write("/etc/asound.conf", conf).ok();
                println!("WSL2 audio bridge installed.");
            }
        } else if std::process::Command::new("dnf").arg("--version").output().is_ok() {
            println!("Detected Fedora — installing...");
            run_shell("sudo", &["dnf", "install", "-y",
                "gcc", "pkgconf-pkg-config", "alsa-lib-devel",
                "pulseaudio-libs-devel", "clang-devel"])?;
        } else if std::process::Command::new("pacman").arg("--version").output().is_ok() {
            println!("Detected Arch — installing...");
            run_shell("sudo", &["pacman", "-S", "--noconfirm",
                "base-devel", "pkgconf", "alsa-lib", "pulseaudio", "clang"])?;
        } else {
            eprintln!("Could not detect a supported package manager.");
            eprintln!("Please install manually: gcc, pkg-config, alsa-lib-dev, pulseaudio-dev, libclang-dev, libv4l-dev");
            std::process::exit(1);
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
        if std::process::Command::new("apt-get").arg("--version").output().is_ok() {
            println!("Detected Debian/Ubuntu/WSL — installing...");
            run_shell("sudo", &["apt-get", "update"])?;
            run_shell("sudo", &["apt-get", "install", "-y",
                "build-essential", "pkg-config", "libclang-dev"])?;
        } else if std::process::Command::new("dnf").arg("--version").output().is_ok() {
            println!("Detected Fedora — installing...");
            run_shell("sudo", &["dnf", "install", "-y",
                "gcc", "pkgconf-pkg-config", "clang-devel"])?;
        } else if std::process::Command::new("pacman").arg("--version").output().is_ok() {
            println!("Detected Arch — installing...");
            run_shell("sudo", &["pacman", "-S", "--noconfirm",
                "base-devel", "pkgconf", "clang"])?;
        } else {
            eprintln!("Could not detect a supported package manager.");
            eprintln!("Please install manually: gcc, pkg-config, libclang-dev");
            std::process::exit(1);
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
    println!("Updating Starling...");
    let status = std::process::Command::new("cargo")
        .args(["install", "--git", "https://forgejo.hearthhome.lol/Saltfault/Starling.git"])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
    if status.success() {
        println!("✓ Starling updated to the latest version");
    } else {
        anyhow::bail!("update failed (exit code: {:?})", status.code());
    }
    Ok(())
}

fn update_tui() -> anyhow::Result<()> {
    println!("Updating Starling TUI...");
    let status = std::process::Command::new("cargo")
        .args(["install", "starling-tui", "--git",
            "https://forgejo.hearthhome.lol/Saltfault/Starling-TUI.git"])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
    if status.success() {
        println!("✓ Starling TUI updated to the latest version");
    } else {
        anyhow::bail!("update failed (exit code: {:?})", status.code());
    }
    Ok(())
}

fn update_server() -> anyhow::Result<()> {
    println!("Updating Starling Server...");
    let status = std::process::Command::new("cargo")
        .args(["install", "starling-server", "--git",
            "https://forgejo.hearthhome.lol/Saltfault/Starling-Server.git"])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
    if status.success() {
        println!("✓ Starling Server updated to the latest version");
    } else {
        anyhow::bail!("update failed (exit code: {:?})", status.code());
    }
    Ok(())
}

fn install_server() -> anyhow::Result<()> {
    println!("Installing Starling Server...");
    let status = std::process::Command::new("cargo")
        .args(["install", "--git", "https://forgejo.hearthhome.lol/Saltfault/Starling-Server.git"])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
    if status.success() {
        println!("✓ Starling Server installed");
        Ok(())
    } else {
        anyhow::bail!("install failed (exit code: {:?})", status.code());
    }
}

fn print_help() {
    println!("Starling v{} — federated p2p communications", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage:");
    println!("  starling install tui            install the TUI client");
    println!("  starling install server         install the headless roost server");
    println!("  starling setup tui              install TUI system dependencies");
    println!("  starling setup server           install Server system dependencies");
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
