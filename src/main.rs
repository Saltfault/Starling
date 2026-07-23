fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);

    match cmd {
        Some("install") => match args.get(2).map(String::as_str) {
            Some("tui") => install_tui(),
            Some("server") => install_server(),
            _ => {
                eprintln!("Usage: starling install <tui|server>");
                std::process::exit(1);
            }
        },
        Some("help" | "--help" | "-h") | None => {
            print_help();
            Ok(())
        }
        _ => {
            let installed = check_installed();
            match installed {
                Installed::Tui => forward_tui(&args[1..]),
                Installed::Server => forward_server(&args[1..]),
                Installed::Both => forward_tui(&args[1..]),
                Installed::None => {
                    eprintln!("Unknown command: {}", cmd.unwrap());
                    eprintln!("Run 'starling help' for usage.");
                    std::process::exit(1);
                }
            }
        }
    }
}

enum Installed {
    None,
    Tui,
    Server,
    Both,
}

fn check_installed() -> Installed {
    let tui = which("starling-tui");
    let server = which("starling-server");
    match (tui, server) {
        (true, true) => Installed::Both,
        (true, false) => Installed::Tui,
        (false, true) => Installed::Server,
        (false, false) => Installed::None,
    }
}

fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path).any(|dir| {
                let candidate = dir.join(if cfg!(windows) {
                    format!("{name}.exe")
                } else {
                    name.to_string()
                });
                candidate.is_file()
            })
        })
        .unwrap_or(false)
}

fn forward_tui(args: &[String]) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new("starling-tui");
    cmd.args(args);
    let status = cmd.status().map_err(|e| anyhow::anyhow!("failed to run starling-tui: {e}"))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn forward_server(args: &[String]) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new("starling-server");
    cmd.args(args);
    let status = cmd.status().map_err(|e| anyhow::anyhow!("failed to run starling-server: {e}"))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn install_tui() -> anyhow::Result<()> {
    println!("Installing Starling TUI...");
    let status = std::process::Command::new("cargo")
        .args([
            "install",
            "--git",
            "https://forgejo.hearthhome.lol/Saltfault/Starling-TUI.git",
        ])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run cargo: {e}"))?;
    if status.success() {
        println!("✓ Starling TUI installed");
        Ok(())
    } else {
        anyhow::bail!("install failed (exit code: {:?})", status.code());
    }
}

fn install_server() -> anyhow::Result<()> {
    println!("Installing Starling Server...");
    let status = std::process::Command::new("cargo")
        .args([
            "install",
            "--git",
            "https://forgejo.hearthhome.lol/Saltfault/Starling-Server.git",
        ])
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
    let installed = check_installed();

    println!("Starling installer v{} — federated p2p communications", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage:");
    println!("  starling install tui            install the TUI client");
    println!("  starling install server         install the headless roost server");
    println!("  starling help                   print this help");
    println!();

    match installed {
        Installed::Both => {
            println!("Installed components: TUI + Server");
            println!();
            println!("TUI commands (starling-tui):");
            println!("  starling join <code>                    join a flock or roost");
            println!("  starling open                           open the TUI");
            println!("  starling leave <code>                   leave a flock or roost");
            println!("  starling list                           list flocks and roosts");
            println!("  starling setup                          configure profile and audio");
            println!("  starling doctor                         diagnose setup");
            println!("  starling logs                           show log file path");
            println!("  starling tui version                    print version");
            println!("  starling tui update                     update to the latest version");
            println!("  starling tui uninstall                  uninstall the TUI");
            println!();
            println!("Server commands (starling-server):");
            println!("  starling roost create   <name>          create a new roost");
            println!("  starling roost open     <name>          start a roost (blocks)");
            println!("  starling roost close    <name>          stop a running roost");
            println!("  starling roost destroy  <name>          delete a roost and all data");
            println!("  starling roost setup    <name>          alias for create");
            println!("  starling roost invite   <name>          show invite code");
            println!("  starling roost status   <name>          show roost info");
            println!("  starling roost doctor   <name>          diagnose a roost");
            println!("  starling roost logs     <name>          show log info");
            println!("  starling roost members  <name>          list members (coming)");
            println!("  starling roost channel add <n> <ch>    add a channel (coming)");
            println!("  starling roost channel remove <n> <ch> remove a channel (coming)");
            println!("  starling server version                print version");
            println!("  starling server update                 update to the latest version");
            println!("  starling server uninstall              uninstall the server");
        }
        Installed::Tui => {
            println!("Installed components: TUI");
            println!();
            println!("Commands:");
            println!("  starling join <code>                    join a flock or roost");
            println!("  starling open                           open the TUI");
            println!("  starling leave <code>                   leave a flock or roost");
            println!("  starling list                           list flocks and roosts");
            println!("  starling setup                          configure profile and audio");
            println!("  starling doctor                         diagnose setup");
            println!("  starling logs                           show log file path");
            println!("  starling tui version                    print version");
            println!("  starling tui update                     update to the latest version");
            println!("  starling tui uninstall                  uninstall the TUI");
        }
        Installed::Server => {
            println!("Installed components: Server");
            println!();
            println!("Commands:");
            println!("  starling roost create   <name>          create a new roost");
            println!("  starling roost open     <name>          start a roost (blocks)");
            println!("  starling roost close    <name>          stop a running roost");
            println!("  starling roost destroy  <name>          delete a roost and all data");
            println!("  starling roost setup    <name>          alias for create");
            println!("  starling roost invite   <name>          show invite code");
            println!("  starling roost status   <name>          show roost info");
            println!("  starling roost doctor   <name>          diagnose a roost");
            println!("  starling roost logs     <name>          show log info");
            println!("  starling roost members  <name>          list members (coming)");
            println!("  starling roost channel add <n> <ch>    add a channel (coming)");
            println!("  starling roost channel remove <n> <ch> remove a channel (coming)");
            println!("  starling server version                print version");
            println!("  starling server update                 update to the latest version");
            println!("  starling server uninstall              uninstall the server");
        }
        Installed::None => {
            println!("No components installed.");
            println!("Install the TUI:   starling install tui");
            println!("Install the Server: starling install server");
        }
    }
}
