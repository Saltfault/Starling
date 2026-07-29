const URL_STARLING: &str = "https://forgejo.hearthhome.lol/Saltfault/Starling.git";
const URL_TUI: &str = "https://forgejo.hearthhome.lol/Saltfault/Starling-TUI.git";
const URL_SERVER: &str = "https://forgejo.hearthhome.lol/Saltfault/Starling-Server.git";

/// Remove stale .old backup from a prior update that didn't clean up
fn cleanup_old_backup() {
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    if home.is_empty() {
        return;
    }
    let old = std::path::PathBuf::from(home)
        .join(".cargo")
        .join("bin")
        .join("starling.old");
    if old.exists() {
        let _ = std::fs::remove_file(&old);
    }
}

fn main() -> anyhow::Result<()> {
    cleanup_old_backup();
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
                let mut results: Vec<(&str, anyhow::Result<()>)> =
                    vec![("launcher", update_self())];
                if !tui_missing() {
                    results.push((
                        "tui",
                        update_pkg("Starling TUI", URL_TUI, install_deps_tui),
                    ));
                }
                if !server_missing() {
                    results.push((
                        "server",
                        update_pkg("Starling Server", URL_SERVER, install_deps_server),
                    ));
                }
                if results.len() == 1 {
                    println!("Nothing installed — run `starling install tui` or `starling install server` first.");
                    return Ok(());
                }
                for (name, r) in &results {
                    println!(
                        "{name}: {}",
                        if r.is_ok() { "ok" } else { "failed (see log)" }
                    );
                }
                Ok(())
            }
            Some(other) => {
                eprintln!("Unknown update target: {other}");
                eprintln!("Usage: starling update [tui|server]");
                std::process::exit(1);
            }
        },

        Some("leave") => {
            if tui_missing() {
                eprintln!("install the TUI first: starling install tui");
                std::process::exit(1);
            }
            let code = args.get(2).cloned().unwrap_or_else(|| {
                eprintln!("Usage: starling leave <code>");
                std::process::exit(1);
            });
            exec("starling-tui", &["leave", &code])
        }
        Some("list") => {
            let roosts_dir = config_dir().join("roosts");
            if !roosts_dir.exists() {
                println!("No roosts found. Create one with: starling roost create <name>");
                return Ok(());
            }
            let mut count = 0;
            for entry in std::fs::read_dir(&roosts_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if path.join("identity.key").exists() {
                        println!("  roost: {name}");
                    } else {
                        println!("  roost: {name} (incomplete)");
                    }
                    count += 1;
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
            if std::process::Command::new("cargo")
                .arg("--version")
                .output()
                .is_ok()
            {
                println!("  ✓ cargo installed");
            } else {
                println!("  ✗ cargo not found — install Rust: https://rustup.rs");
            }

            // Per‑roost health checks
            if roosts_dir.exists() {
                println!();
                println!("Roost health:");
                let server_available = std::process::Command::new("starling-server")
                    .arg("--version")
                    .output()
                    .is_ok();
                if !server_available {
                    println!("  (starling-server not installed — run `starling install server`)");
                } else {
                    for entry in std::fs::read_dir(&roosts_dir)? {
                        let entry = entry?;
                        if entry.file_type()?.is_dir() {
                            let name = entry.file_name().to_string_lossy().to_string();
                            print!("  {name}: ");
                            match std::process::Command::new("starling-server")
                                .args(["roost", "doctor", &name])
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .status()
                            {
                                Ok(status) if status.success() => println!("ok"),
                                Ok(_) => println!("issue detected"),
                                Err(e) => println!("error running doctor: {e}"),
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        Some("logs") => {
            println!("Starling logs:");
            println!(
                "  {}",
                config_dir().join("logs").join("latest.log").display()
            );
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

        Some("profile") => {
            if tui_missing() {
                return run_headless_profile_editor(&args);
            }
            exec("starling-tui", &["profile"])
        }

        Some("open") => {
            if tui_missing() {
                eprintln!("install the TUI first: starling install tui");
                std::process::exit(1);
            }
            exec("starling-tui", &[])
        }
        Some("join") => {
            if tui_missing() {
                eprintln!("install the TUI first: starling install tui");
                std::process::exit(1);
            }
            let code = args.get(2).cloned().unwrap_or_else(|| {
                eprintln!("Usage: starling join <code>");
                std::process::exit(1);
            });
            exec("starling-tui", &["join", &code])
        }

        Some("roost") => {
            if args
                .get(2)
                .map(|s| s == "--help" || s == "-h")
                .unwrap_or(false)
            {
                print_roost_help();
                return Ok(());
            }
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
            Some("uninstall") => {
                uninstall_pkg("starling-server", "Starling Server")?;
                if args.iter().any(|a| a == "--purge-data") {
                    remove_server_data()?;
                } else {
                    println!("(use --purge-data to also remove roosts and logs)");
                }
                Ok(())
            }
            _ => {
                eprintln!("Usage: starling server <version|update|uninstall>");
                std::process::exit(1);
            }
        },

        Some("uninstall") => {
            let dir = config_dir();
            if !dir.exists() {
                println!("No Starling data found at {}", dir.display());
                return Ok(());
            }
            let force = args.get(2).map(String::as_str) == Some("--force");
            if !force {
                eprintln!("This will delete ALL Starling data:");
                eprintln!("  {}", dir.display());
                eprintln!("  (profiles, identity keys, roosts, logs, history)");
                eprintln!();
                eprintln!("Run 'starling uninstall --force' to confirm.");
                std::process::exit(1);
            }
            println!("Deleting all Starling data...");
            std::fs::remove_dir_all(&dir)?;
            println!("✓ All Starling data deleted from {}", dir.display());
            Ok(())
        }
        Some("--version") | Some("-V") => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }

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

fn tui_missing() -> bool {
    std::process::Command::new("starling-tui")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
}

fn server_missing() -> bool {
    std::process::Command::new("starling-server")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_err()
}

fn exec(bin: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new(bin)
        .args(args)
        .status()
        .map_err(|e| {
            anyhow::anyhow!(
                "{bin} not found — run `starling install {}` first: {e}",
                if bin == "starling-tui" {
                    "tui"
                } else {
                    "server"
                }
            )
        })?;
    std::process::exit(status.code().unwrap_or(1));
}

fn config_dir() -> std::path::PathBuf {
    starling::config::Profile::config_dir()
}

fn cargo_install(url: &str) -> anyhow::Result<()> {
    let mut command = std::process::Command::new("cargo");
    // `--force` overwrites an existing install of the same version instead of
    // erroring (cargo refuses without it once the binary is already on PATH),
    // so `starling install tui` / `starling update tui` can re-run in place.
    command.args(["install", "--jobs", "2", "--force", "--git", url]);
    if url == URL_TUI {
        command.args(["--features", "audio,video"]);
    } else if url == URL_SERVER {
        command.arg("--no-default-features");
    }
    let status = command
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("cargo install failed (exit code: {:?})", status.code())
    }
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
        println!("✓ {name} uninstalled (profile and data preserved)");
        Ok(())
    } else {
        anyhow::bail!("uninstall failed (exit code: {:?})", status.code());
    }
}

fn remove_server_data() -> anyhow::Result<()> {
    let dir = config_dir();
    let roosts = dir.join("roosts");
    let logs = dir.join("logs");
    let mut removed = false;
    if roosts.exists() {
        println!("Removing roosts directory...");
        std::fs::remove_dir_all(&roosts)?;
        removed = true;
    }
    if logs.exists() {
        println!("Removing logs directory...");
        std::fs::remove_dir_all(&logs)?;
        removed = true;
    }
    if removed {
        println!("✓ Server data purged");
    } else {
        println!("No server data found to purge at {}", dir.display());
    }
    Ok(())
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
    if std::process::Command::new("apt-get")
        .arg("--version")
        .output()
        .is_ok()
    {
        println!("Detected Debian/Ubuntu/WSL — installing...");
        run_shell("sudo", &["apt-get", "update"])?;
        let mut apt = vec!["apt-get", "install", "-y"];
        apt.extend(packages);
        run_shell("sudo", &apt)?;
        if let Some(wsl_pkgs) = extra_wsl
            && std::path::Path::new("/mnt/wslg").exists()
            && !std::path::Path::new("/etc/asound.conf").exists()
        {
            println!("Setting up WSL2 audio bridge...");
            let mut wsl = vec!["apt-get", "install", "-y"];
            wsl.extend(wsl_pkgs);
            run_shell("sudo", &wsl)?;
            let conf = "pcm.!default {\ntype pulse\n}\nctl.!default {\ntype pulse\n}\n";
            run_shell(
                "sudo",
                &[
                    "sh",
                    "-c",
                    &format!(
                        "printf '%s' '{}' > /etc/asound.conf",
                        conf.replace('\'', "'\\''"),
                    ),
                ],
            )?;
            println!("WSL2 audio bridge installed.");
        }
    } else if std::process::Command::new("dnf")
        .arg("--version")
        .output()
        .is_ok()
    {
        println!("Detected Fedora — installing...");
        let mut dnf = vec!["dnf", "install", "-y"];
        dnf.extend(packages);
        run_shell("sudo", &dnf)?;
    } else if std::process::Command::new("pacman")
        .arg("--version")
        .output()
        .is_ok()
    {
        println!("Detected Arch — installing...");
        let mut pac = vec!["pacman", "-S", "--needed", "--noconfirm"];
        pac.extend(packages);
        run_shell("sudo", &pac)?;
    } else {
        eprintln!("Could not detect a supported package manager.");
        return Err(anyhow::anyhow!("unsupported package manager"));
    }
    Ok(())
}

fn install_deps_tui() -> anyhow::Result<()> {
    if cfg!(target_os = "linux") {
        let r = install_linux_deps(
            &[
                "build-essential",
                "pkg-config",
                "libasound2-dev",
                "libpulse-dev",
                "libclang-dev",
                "libv4l-dev",
            ],
            Some(&["libasound2-plugins"]),
        );
        if let Err(e) = r {
            eprintln!(
                "Please install manually: gcc, pkg-config, alsa-lib-dev, pulseaudio-dev, libclang-dev, libv4l-dev"
            );
            return Err(e);
        }
    } else if cfg!(target_os = "macos") {
        if std::process::Command::new("brew")
            .arg("--version")
            .output()
            .is_ok()
        {
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
        let r = install_linux_deps(&["build-essential", "pkg-config"], None);
        if let Err(e) = r {
            eprintln!("Please install manually: gcc, pkg-config");
            return Err(e);
        }
    } else if cfg!(target_os = "macos") {
        if std::process::Command::new("brew")
            .arg("--version")
            .output()
            .is_ok()
        {
            println!("Detected macOS (Homebrew) — installing...");
            run_shell("brew", &["install", "pkg-config"])?;
        } else {
            eprintln!("Please install Homebrew first: https://brew.sh");
            eprintln!("Then run: brew install pkg-config");
            std::process::exit(1);
        }
    } else if cfg!(target_os = "windows") {
        if std::process::Command::new("winget")
            .arg("--version")
            .output()
            .is_ok()
        {
            println!("Detected winget — installing VS Build Tools...");
            run_shell(
                "winget",
                &[
                    "install",
                    "--id",
                    "Microsoft.VisualStudio.2022.BuildTools",
                    "--silent",
                    "--accept-package-agreements",
                    "--override",
                    "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended",
                ],
            )?;
        } else {
            println!("On Windows, install Visual Studio Build Tools:");
            println!("  https://visualstudio.microsoft.com/visual-cpp-build-tools/");
            println!("Select 'Desktop development with C++'.");
        }
    }
    println!("✓ Server system dependencies installed");
    Ok(())
}

fn update_self() -> anyhow::Result<()> {
    if cfg!(windows) {
        println!("Updating Starling...");
        let script = format!(
            r#"$exe = "$env:USERPROFILE\.cargo\bin\starling.exe"
$old = "$env:USERPROFILE\.cargo\bin\starling.old"
try {{
    Move-Item $exe $old -Force
    cargo install --jobs 2 --git {URL_STARLING}
    if ($LASTEXITCODE -ne 0) {{ throw "cargo install failed with exit code $LASTEXITCODE" }}
    Remove-Item $old -ErrorAction SilentlyContinue
    exit 0
}}
catch {{
    if (Test-Path $old) {{ Move-Item $old $exe -Force }}
    exit 1
}}"#
        );
        let ps = std::env::temp_dir().join(format!("starling-update-{}.ps1", uuid::Uuid::new_v4()));
        let mut script_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&ps)
            .map_err(|e| anyhow::anyhow!("failed to create updater script: {e}"))?;
        std::io::Write::write_all(&mut script_file, script.as_bytes())
            .and_then(|()| script_file.sync_all())
            .map_err(|e| anyhow::anyhow!("failed to write updater script: {e}"))?;
        drop(script_file);
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&ps)
            .status();
        let _ = std::fs::remove_file(&ps);
        let status = status.map_err(|e| anyhow::anyhow!("failed to run PowerShell: {e}"))?;
        if status.success() {
            println!("✓ Starling updated to the latest version");
            Ok(())
        } else {
            eprintln!("Update failed. To update manually, run:");
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

fn run_headless_profile_editor(args: &[String]) -> anyhow::Result<()> {
    match args.get(2).map(String::as_str) {
        Some("show") => show_profile(),
        Some("set") => {
            let field = args.get(3).map(String::as_str);
            let value = args.get(4).map(|s| s.as_str());
            set_profile_field(field, value)
        }
        Some(sub) => {
            eprintln!("Unknown profile subcommand: {sub}");
            eprintln!("Usage: starling profile [show|set <field> <value>]");
            std::process::exit(1);
        }
        None => interactive_profile_editor(),
    }
}

fn show_profile() -> anyhow::Result<()> {
    let profile = starling::config::Profile::load().unwrap_or_default();
    println!("Profile:");
    println!(
        "  name:           {}",
        if profile.name.is_empty() {
            "(unset)"
        } else {
            &profile.name
        }
    );
    println!(
        "  pronouns:       {}",
        if profile.pronouns.is_empty() {
            "(unset)"
        } else {
            &profile.pronouns
        }
    );
    println!(
        "  input device:   {}",
        profile
            .input_device
            .as_deref()
            .unwrap_or("(system default)")
    );
    println!(
        "  output device:  {}",
        profile
            .output_device
            .as_deref()
            .unwrap_or("(system default)")
    );
    println!(
        "  camera index:   {}",
        profile
            .camera_index
            .map(|i| i.to_string())
            .unwrap_or_else(|| "(default)".into())
    );
    println!("  text color:     {}", profile.text_color);
    println!(
        "  bg color:       {}",
        if profile.bg_color.is_empty() {
            "(transparent)"
        } else {
            &profile.bg_color
        }
    );
    println!("  border color:   {}", profile.border_color);
    println!("  accent color:   {}", profile.accent_color);
    println!("  author color:   {}", profile.author_color);
    println!("  selection color:{}", profile.selection_color);
    println!("  dim color:      {}", profile.dim_color);
    Ok(())
}

fn set_profile_field(field: Option<&str>, value: Option<&str>) -> anyhow::Result<()> {
    let field = field.unwrap_or_else(|| {
        eprintln!("Usage: starling profile set <field> <value>");
        eprintln!("Fields: name, pronouns, input-device, output-device, camera-index,");
        eprintln!("        text-color, bg-color, border-color, accent-color,");
        eprintln!("        author-color, selection-color, dim-color");
        std::process::exit(1);
    });
    let value = value.unwrap_or_else(|| {
        eprintln!("Missing value for field '{field}'");
        eprintln!("Usage: starling profile set {field} <value>");
        std::process::exit(1);
    });

    let mut profile = starling::config::Profile::load().unwrap_or_default();

    match field {
        "name" => profile.name = value.to_string(),
        "pronouns" => profile.pronouns = value.to_string(),
        "input-device" | "input_device" => profile.input_device = Some(value.to_string()),
        "output-device" | "output_device" => profile.output_device = Some(value.to_string()),
        "camera-index" | "camera_index" => {
            profile.camera_index = Some(
                value
                    .parse()
                    .map_err(|_| anyhow::anyhow!("camera-index must be a number"))?,
            );
        }
        "text-color" | "text_color" => profile.text_color = value.to_string(),
        "bg-color" | "bg_color" => profile.bg_color = value.to_string(),
        "border-color" | "border_color" => profile.border_color = value.to_string(),
        "accent-color" | "accent_color" => profile.accent_color = value.to_string(),
        "author-color" | "author_color" => profile.author_color = value.to_string(),
        "selection-color" | "selection_color" => profile.selection_color = value.to_string(),
        "dim-color" | "dim_color" => profile.dim_color = value.to_string(),
        _ => {
            eprintln!("Unknown field: {field}");
            eprintln!(
                "Available fields: name, pronouns, input-device, output-device, camera-index,"
            );
            eprintln!("                  text-color, bg-color, border-color, accent-color,");
            eprintln!("                  author-color, selection-color, dim-color");
            std::process::exit(1);
        }
    }

    profile.save()?;
    println!("✓ Profile updated: {field} = {value}");
    Ok(())
}

fn interactive_profile_editor() -> anyhow::Result<()> {
    let mut profile = starling::config::Profile::load().unwrap_or_default();

    println!("Starling Profile Editor (headless)");
    println!("Press Enter to keep the current value.\n");

    profile.name = prompt("Display name", &profile.name)?;
    profile.pronouns = prompt("Pronouns", &profile.pronouns)?;
    profile.input_device = prompt_optional("Input device", &profile.input_device)?;
    profile.output_device = prompt_optional("Output device", &profile.output_device)?;
    profile.camera_index = {
        let current = profile
            .camera_index
            .map(|i| i.to_string())
            .unwrap_or_default();
        let input = prompt("Camera index (blank for default)", &current)?;
        if input.is_empty() {
            None
        } else {
            Some(
                input
                    .parse()
                    .map_err(|_| anyhow::anyhow!("camera index must be a number"))?,
            )
        }
    };

    println!("\nColor settings (hex codes, e.g. #FF0000):");
    profile.text_color = prompt("Text color", &profile.text_color)?;
    profile.bg_color = prompt(
        "Background color (blank for transparent)",
        &profile.bg_color,
    )?;
    profile.border_color = prompt("Border color", &profile.border_color)?;
    profile.accent_color = prompt("Accent color", &profile.accent_color)?;
    profile.author_color = prompt("Author color", &profile.author_color)?;
    profile.selection_color = prompt("Selection color", &profile.selection_color)?;
    profile.dim_color = prompt("Dim color", &profile.dim_color)?;

    profile.save()?;
    println!("\n✓ Profile saved.");
    Ok(())
}

fn prompt(label: &str, default: &str) -> anyhow::Result<String> {
    let default_display = if default.is_empty() {
        "(unset)"
    } else {
        default
    };
    print!("{label} [{default_display}]: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim().to_string();
    Ok(if input.is_empty() {
        default.to_string()
    } else {
        input
    })
}

fn prompt_optional(label: &str, default: &Option<String>) -> anyhow::Result<Option<String>> {
    let default_display = default.as_deref().unwrap_or("(system default)");
    print!("{label} [{default_display}]: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim().to_string();
    Ok(if input.is_empty() {
        default.clone()
    } else {
        Some(input)
    })
}

fn print_roost_help() {
    println!(
        "Starling v{} — roost subcommands",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("Usage:");
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
}

fn print_help() {
    println!(
        "Starling v{} — federated p2p communications",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("Usage:");
    println!("  starling install tui            install the TUI client");
    println!("  starling install server         install the headless roost server");
    println!();
    println!("  starling profile                configure profile (headless fallback)");
    println!("  starling profile show           display current profile");
    println!("  starling profile set <f> <v>    set a profile field non-interactively");
    println!("  starling join <code>            join a flock or roost");
    println!("  starling open                   open the TUI");
    println!("  starling leave <code>           leave a flock or roost");
    println!("  starling list                   list roosts on disk");
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
    println!("  starling uninstall              delete ALL Starling data (requires --force)");
    println!();
    println!("  starling update                update Starling, TUI, and Server");
    println!("  starling update tui            update only the TUI");
    println!("  starling update server         update only the Server");
    println!("  starling help                  print this help");
    println!("  starling --version              print launcher version");
}
