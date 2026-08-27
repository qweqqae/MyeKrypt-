use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use myekrypt::crypto::{self, EncryptOptions};
use myekrypt::{workspace, Progress, Secret};

const USAGE: &str = "\
cmf - MyeKrypt command line

USAGE
    cmf                        open the interactive workspace
    cmf [OPTIONS] <PATH>...    encrypt each path into the workspace
    cmf -d [OPTIONS] <PATH>... decrypt each container

OPTIONS
    -d, --decrypt        decrypt instead of encrypt
    -H, --hwid           bind the container to this machine (no recovery key)
        --no-hwid        do not bind, and do not ask
    -s, --shred          overwrite and delete the source after encrypting
        --no-shred       keep the source, and do not ask
    -o, --out <DIR>      write results here instead of the workspace
    -h, --help           show this text
    -V, --version        show the version

Anything not given as a flag is asked for interactively.
The workspace defaults to ./source and follows $MYEKRYPT_HOME when set.";

pub fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let parsed = match Options::parse(args)? {
        Some(parsed) => parsed,
        None => return Ok(()),
    };

    let destination = parsed.output.clone().unwrap_or_else(|| workspace::root().to_path_buf());
    std::fs::create_dir_all(&destination)?;

    if parsed.decrypt {
        do_decrypt(&parsed, &destination)
    } else {
        do_encrypt(&parsed, &destination)
    }
}

struct Options {
    decrypt: bool,
    hwid: Option<bool>,
    shred: Option<bool>,
    output: Option<PathBuf>,
    paths: Vec<PathBuf>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Option<Options>, String> {
        let mut parsed =
            Options { decrypt: false, hwid: None, shred: None, output: None, paths: Vec::new() };
        let mut positional_only = false;
        let mut iter = args.iter();

        while let Some(arg) = iter.next() {
            if positional_only {
                parsed.paths.push(expand(arg));
                continue;
            }
            match arg.as_str() {
                "--" => positional_only = true,
                "-h" | "--help" => {
                    println!("{USAGE}");
                    return Ok(None);
                }
                "-V" | "--version" => {
                    println!("cmf {}", env!("CARGO_PKG_VERSION"));
                    return Ok(None);
                }
                "-d" | "--decrypt" => parsed.decrypt = true,
                "-H" | "--hwid" => parsed.hwid = Some(true),
                "--no-hwid" => parsed.hwid = Some(false),
                "-s" | "--shred" => parsed.shred = Some(true),
                "--no-shred" => parsed.shred = Some(false),
                "-o" | "--out" => {
                    let value = iter.next().ok_or("--out needs a directory")?;
                    parsed.output = Some(expand(value));
                }
                other if other.starts_with('-') && other.len() > 1 => {
                    return Err(format!("unknown option '{other}' (try --help)"));
                }
                other => parsed.paths.push(expand(other)),
            }
        }

        if parsed.paths.is_empty() {
            return Err("no paths given (try --help)".to_owned());
        }
        Ok(Some(parsed))
    }
}

fn do_encrypt(options: &Options, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for path in &options.paths {
        if !path.exists() {
            return Err(format!("not found: {}", path.display()).into());
        }
    }

    let hwid = match options.hwid {
        Some(value) => value,
        None => yes_no("Bind to this machine only? There is no recovery key. [y/N]: ")?,
    };
    let shred = match options.shred {
        Some(value) => value,
        None => yes_no("Overwrite and delete the original afterwards? [y/N]: ")?,
    };

    let password = ask_pass2()?;
    crypto::check_pass(password.as_str())?;

    for path in &options.paths {
        let name = path
            .file_name()
            .ok_or_else(|| format!("{} has no file name", path.display()))?
            .to_string_lossy()
            .into_owned();
        let target = myekrypt::fsutil::unused_path(&crypto::enc_name(&destination.join(name)));

        let source = path.clone();
        let secret = password.clone_z();
        let target_for_worker = target.clone();
        let settings = EncryptOptions { hwid, shred_source: shred, overwrite: false };

        let written = run_with_bar(&format!("Encrypting {}", path.display()), move |progress| {
            crypto::encrypt_file(&source, &target_for_worker, &secret, settings, progress)
        })?;
        println!("  -> {}", written.display());
    }
    Ok(())
}

fn do_decrypt(options: &Options, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut hint = options.hwid;
    for path in &options.paths {
        let info = crypto::peek(path)
            .ok_or_else(|| format!("{} is not a container", path.display()))?;
        if info.hwid.is_none() && hint.is_none() {
            hint = Some(yes_no("This container predates device flags. Was it bound to this machine? [y/N]: ")?);
        }
    }

    let password = ask_pass("Password: ")?;

    for path in &options.paths {
        let source = path.clone();
        let secret = password.clone_z();
        let output = destination.to_path_buf();

        let written = run_with_bar(&format!("Decrypting {}", path.display()), move |progress| {
            crypto::decrypt(&source, &output, &secret, hint, progress)
        })?;
        println!("  -> {}", written.display());
    }
    Ok(())
}

fn run_with_bar<T, F>(label: &str, work: F) -> Result<T, myekrypt::Error>
where
    T: Send + 'static,
    F: FnOnce(&Progress) -> Result<T, myekrypt::Error> + Send + 'static,
{
    let progress = Progress::new();
    let worker_progress = progress.clone();
    let handle = thread::spawn(move || work(&worker_progress));

    let mut stderr = io::stderr();
    let animate = stderr.is_terminal();
    if !animate {
        eprintln!("{label}");
    }
    while !handle.is_finished() {
        if animate {
            let rendered = match progress.ratio() {
                Some(ratio) => format!("{:>3.0}%", ratio * 100.0),
                None => "deriving key".to_owned(),
            };
            let _ = write!(stderr, "\r\x1b[K{label} {rendered}");
            let _ = stderr.flush();
        }
        thread::sleep(Duration::from_millis(120));
    }
    if animate {
        let _ = writeln!(stderr, "\r\x1b[K{label} done");
        let _ = stderr.flush();
    }

    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(myekrypt::Error::Other("the worker thread panicked".to_owned())),
    }
}

struct RawMode;

impl RawMode {
    fn enable() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(RawMode)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

fn ask_pass(prompt: &str) -> Result<Secret, Box<dyn std::error::Error>> {
    let mut stdout = io::stdout();
    write!(stdout, "{prompt}")?;
    stdout.flush()?;

    let _raw = RawMode::enable()?;
    let mut secret = Secret::new();

    loop {
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            write!(stdout, "\r\n")?;
            return Err("cancelled".into());
        }
        match key.code {
            KeyCode::Enter => break,
            KeyCode::Esc => {
                write!(stdout, "\r\n")?;
                return Err("cancelled".into());
            }
            KeyCode::Backspace => {
                if !secret.is_empty() {
                    secret.pop();
                    write!(stdout, "\u{8} \u{8}")?;
                    stdout.flush()?;
                }
            }
            KeyCode::Char(c) => {
                secret.push(c);
                write!(stdout, "*")?;
                stdout.flush()?;
            }
            _ => {}
        }
    }

    write!(stdout, "\r\n")?;
    stdout.flush()?;
    Ok(secret)
}

fn ask_pass2() -> Result<Secret, Box<dyn std::error::Error>> {
    loop {
        let first = ask_pass("Password: ")?;
        let second = ask_pass("Repeat password: ")?;
        if first.matches(&second) {
            return Ok(first);
        }
        eprintln!("Passwords did not match, try again.");
    }
}

fn yes_no(prompt: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let mut stdout = io::stdout();
    write!(stdout, "{prompt}")?;
    stdout.flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

fn expand(raw: &str) -> PathBuf {
    let trimmed = raw.trim().trim_matches('\'').trim_matches('"');
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(trimmed)
}
