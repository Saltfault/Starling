use sha2::Digest;
use std::io::Read;

const BASE_URL: &str = "https://forgejo.hearthhome.lol/Saltfault";
const API_URL: &str = "https://forgejo.hearthhome.lol/api/v1/repos/Saltfault";
const REPO_STARLING: &str = "Starling";
const REPO_TUI: &str = "Starling-TUI";
const REPO_SERVER: &str = "Starling-Server";

/// Remove stale .old backup from a prior update that didn't clean up
fn cleanup_old_backup() {
    let bin = cargo_bin_dir().join("starling.old");
    if bin.exists() {
        let _ = std::fs::remove_file(&bin);
    }
}

fn cargo_bin_dir() -> std::path::PathBuf {
    std::env::var("CARGO_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_default();
            std::path::PathBuf::from(home).join(".cargo")
        })
        .join("bin")
}

fn host_target() -> &'static str {
    if cfg!(target_os = "windows") {
        "x86_64-pc-windows-msvc"
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "aarch64-apple-darwin"
        } else {
            "x86_64-apple-darwin"
        }
    } else {
        if cfg!(target_arch = "aarch64") {
            "aarch64-unknown-linux-gnu"
        } else {
            "x86_64-unknown-linux-gnu"
        }
    }
}

fn download_binary(repo: &str, bin_name: &str) -> anyhow::Result<()> {
    let target = host_target();
    let ext = if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    };
    let asset = format!("{bin_name}-{target}{ext}");
    let tag = get_latest_tag(repo)?;
    let url = format!("{BASE_URL}/{repo}/releases/download/{tag}/{asset}");
    let dest = cargo_bin_dir().join(format!("{bin_name}{ext}"));

    println!("Downloading {bin_name} {tag} ({target})...");
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("download failed: {e}"))?;
    let mut body: Vec<u8> = Vec::new();
    resp.into_reader().read_to_end(&mut body)?;

    // Verify checksum if available
    let sha_url = format!("{BASE_URL}/{repo}/releases/download/{tag}/{bin_name}-{target}.sha256");
    if let Ok(sha_resp) = ureq::get(&sha_url).call() {
        let sha = sha_resp.into_string()?;
        let expected = sha.split_whitespace().next().unwrap_or("");
        let mut hasher = sha2::Sha256::new();
        hasher.update(&body);
        let actual = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        if expected != actual {
            anyhow::bail!("checksum mismatch for {bin_name}: expected {expected}, got {actual}");
        }
    }

    let parent = dest.parent().unwrap();
    std::fs::create_dir_all(parent)?;
    if dest.exists() {
        let backup = parent.join(format!("{bin_name}.old"));
        let _ = std::fs::remove_file(&backup);
        std::fs::rename(&dest, &backup)?;
    }
    std::fs::write(&dest, &body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn get_latest_tag(repo: &str) -> anyhow::Result<String> {
    let url = format!("{API_URL}/{repo}/releases/latest");
    let resp = ureq::get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("failed to fetch latest release: {e}"))?;
    let json: serde_json::Value = resp.into_json()?;
    json["tag_name"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| anyhow::anyhow!("no tag_name in release response"))
}

fn download_self() -> anyhow::Result<()> {
    let current = std::env::current_exe()?;
    let ext = if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    };

    download_binary(REPO_STARLING, "starling")?;
    let new_bin = cargo_bin_dir().join(format!("starling{ext}"));

    // On Windows we can't overwrite the running exe directly, so we write a
    // batch file that swaps the binaries after this process exits.
    if cfg!(windows) && current == new_bin {
        let script = cargo_bin_dir().join("starling-update.bat");
        let old = cargo_bin_dir().join("starling.old");
        std::fs::write(
            &script,
            format!(
                "@echo off\r\n\
             timeout /t 1 /nobreak >nul\r\n\
             move /Y \"{}\" \"{}\"\r\n\
             del \"%~f0\"\r\n",
                old.display(),
                current.display()
            ),
        )?;
        std::process::Command::new("cmd")
            .args(["/C", &script.to_string_lossy()])
            .spawn()?;
        std::process::exit(0);
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    cleanup_old_backup();
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);

    match cmd {
        Some("install") => match args.get(2).map(String::as_str) {
            Some("tui") => install_pkg("Starling TUI", REPO_TUI, "starling-tui"),
            Some("server") => install_pkg("Starling Server", REPO_SERVER, "starling-server"),
            _ => {
                eprintln!("Usage: starling install <tui|server>");
                std::process::exit(1);
            }
        },
        Some("update") => match args.get(2).map(String::as_str) {
            Some("tui") => update_pkg("Starling TUI", REPO_TUI, "starling-tui"),
            Some("server") => update_pkg("Starling Server", REPO_SERVER, "starling-server"),
            None => {
                let launcher_result = download_self();
                let mut updated = vec![("launcher", launcher_result)];
                if !tui_missing() {
                    updated.push(("tui", update_pkg("Starling TUI", REPO_TUI, "starling-tui")));
                }
                if !server_missing() {
                    updated.push((
                        "server",
                        update_pkg("Starling Server", REPO_SERVER, "starling-server"),
                    ));
                }
                for (name, r) in &updated {
                    println!(
                        "{name}: {}",
                        if r.is_ok() { "ok" } else { "failed (see log)" }
                    );
                }
                if updated.len() == 1 {
                    println!(
                        "(only the launcher was updated — install components with `starling install tui` or `starling install server`)"
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
            Some("update") => update_pkg("Starling TUI", REPO_TUI, "starling-tui"),
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
            Some("update") => update_pkg("Starling Server", REPO_SERVER, "starling-server"),
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
            let force = args.get(2).map(String::as_str) == Some("--force");
            if !force {
                eprintln!("This will delete ALL Starling binaries and data:");
                eprintln!("  (launcher, TUI, server, profiles, roosts, logs, history)");
                eprintln!();
                eprintln!("Run 'starling uninstall --force' to confirm.");
                std::process::exit(1);
            }
            // Remove components first
            if !tui_missing() {
                let _ = uninstall_pkg("starling-tui", "Starling TUI");
            }
            if !server_missing() {
                let _ = uninstall_pkg("starling-server", "Starling Server");
            }
            // Remove the launcher itself
            let ext = if cfg!(target_os = "windows") {
                ".exe"
            } else {
                ""
            };
            let me = cargo_bin_dir().join(format!("starling{ext}"));
            if me.exists() {
                if cfg!(windows) {
                    // Schedule deletion after exit via batch file
                    let script = cargo_bin_dir().join("starling-cleanup.bat");
                    std::fs::write(
                        &script,
                        format!(
                            "@echo off\r\ntimeout /t 1 /nobreak >nul\r\ndel /F \"{}\"\r\ndel \"%~f0\"\r\n",
                            me.display()
                        ),
                    )?;
                    std::process::Command::new("cmd")
                        .args(["/C", &script.to_string_lossy()])
                        .spawn()?;
                } else {
                    std::fs::remove_file(&me)?;
                }
            }
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

fn install_pkg(name: &str, repo: &str, bin: &str) -> anyhow::Result<()> {
    println!("Installing {name}...");
    download_binary(repo, bin)?;
    println!("✓ {name} installed");
    Ok(())
}

fn update_pkg(name: &str, repo: &str, bin: &str) -> anyhow::Result<()> {
    println!("Updating {name}...");
    download_binary(repo, bin)?;
    println!("✓ {name} updated to the latest version");
    Ok(())
}

fn uninstall_pkg(bin: &str, name: &str) -> anyhow::Result<()> {
    println!("Uninstalling {name}...");
    let ext = if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    };
    let path = cargo_bin_dir().join(format!("{bin}{ext}"));
    if path.exists() {
        std::fs::remove_file(&path)?;
        println!("✓ {name} uninstalled (profile and data preserved)");
    } else {
        println!("{name} was not installed");
    }
    Ok(())
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
    let has_tui = !tui_missing();
    let has_server = !server_missing();

    println!(
        "Starling v{} — federated p2p communications",
        env!("CARGO_PKG_VERSION")
    );
    println!();

    // ── always available ──
    println!("Usage:");
    println!("  starling install tui            install the TUI client");
    println!("  starling install server         install the headless roost server");
    println!();
    println!("  starling update                 update the launcher");
    if has_tui {
        println!("  starling update tui             update the TUI");
    }
    if has_server {
        println!("  starling update server          update the Server");
    }
    println!();
    println!("  starling uninstall --force      delete ALL Starling data and binaries");
    println!("  starling help                   print this help");
    println!("  starling --version              print launcher version");
    println!();

    // ── profile (always, headless fallback) ──
    println!("Profile:");
    println!("  starling profile                configure profile (headless fallback)");
    println!("  starling profile show           display current profile");
    println!("  starling profile set <f> <v>    set a profile field non-interactively");
    println!();

    if has_tui {
        println!("TUI client:");
        println!("  starling open                   open the TUI");
        println!("  starling join <code>            join a flock or roost");
        println!("  starling leave <code>           leave a flock or roost");
        println!("  starling tui version            print TUI version");
        println!("  starling tui uninstall          uninstall the TUI");
        println!();
    }

    if has_server {
        println!("Roost server:");
        println!("  starling list                   list roosts on disk");
        println!("  starling doctor                 diagnose setup");
        println!("  starling logs                   show log file path");
        println!("  starling server version         print Server version");
        println!("  starling server uninstall       uninstall the Server");
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
        println!();
    }

    if !has_tui && !has_server {
        println!("Run `starling install tui` or `starling install server` to get started.");
    }
}
