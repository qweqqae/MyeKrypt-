use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use myekrypt::{crypto, shred, workspace};

use super::app::{fname, App, Mode, Pending, IDLE_HINT};

pub fn handle(app: &mut App, event: Event) {
    let Event::Key(key) = event else {
        return;
    };
    if key.kind != KeyEventKind::Press {
        return;
    }
    if ctrl_c(&key) {
        app.should_quit = true;
        return;
    }

    match app.mode {
        Mode::Normal => normal(app, key),
        Mode::Command => command(app, key),
        Mode::NewFileName => new_name(app, key),
        Mode::Compose => compose(app, key),
        Mode::Password => password(app, key),
        Mode::PasswordConfirm => pass2(app, key),
        Mode::Editing => editing(app, key),
        Mode::Viewing => viewing(app, key),
        Mode::Documentation => docs(app, key),
        Mode::AskDeviceLock => ask_hwid(app, key),
        Mode::AskShred => ask_shred(app, key),
        Mode::AskLegacyDeviceLock => ask_old_hwid(app, key),
        Mode::AskDelete => ask_del(app, key),
    }
}

fn ctrl_c(key: &KeyEvent) -> bool {
    key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c'))
}

fn normal(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Down | KeyCode::Char('j') => app.next(),
        KeyCode::Up | KeyCode::Char('k') => app.previous(),
        KeyCode::Char('r') => {
            app.reload();
            app.status = "Workspace reloaded.".to_owned();
        }
        KeyCode::Char('i') => {
            app.mode = Mode::Documentation;
            app.status = "Documentation. Esc returns.".to_owned();
        }
        KeyCode::Char('z') => {
            app.mode = Mode::Command;
            app.command_input.clear();
            app.status = "Path to import and encrypt:".to_owned();
        }
        KeyCode::Char('n') => {
            app.filename_input.clear();
            app.wipe_buf();
            app.mode = Mode::NewFileName;
            app.status = "Name for the new encrypted file:".to_owned();
        }
        KeyCode::Char('e') => enc_sel(app),
        KeyCode::Char('d') => dec_sel(app),
        KeyCode::Char('v') => open_sel(app, false),
        KeyCode::Char('m') => open_sel(app, true),
        KeyCode::Char('x') => {
            if let Some(path) = app.cur_path() {
                app.status = format!(
                    "Delete {}?  [s] overwrite and delete  [y] just delete  [Esc] cancel",
                    fname(path)
                );
                app.mode = Mode::AskDelete;
            }
        }
        _ => {}
    }
}

fn enc_sel(app: &mut App) {
    let Some(entry) = app.cur() else {
        app.status = "[-] Nothing selected.".to_owned();
        return;
    };
    if entry.info.is_some() {
        app.status =
            "[-] Already encrypted. Decrypt it first if you want to change the password.".to_owned();
        return;
    }
    let source = entry.path.clone();
    app.start_enc(Pending::EncryptPath { source });
}

fn dec_sel(app: &mut App) {
    let Some(entry) = app.cur() else {
        app.status = "[-] Nothing selected.".to_owned();
        return;
    };
    let Some(info) = entry.info else {
        app.status = "[-] Not an encrypted container.".to_owned();
        return;
    };
    let source = entry.path.clone();
    app.start_dec(Pending::Decrypt { source }, Some(info));
}

fn open_sel(app: &mut App, editable: bool) {
    let Some(entry) = app.cur() else {
        app.status = "[-] Nothing selected.".to_owned();
        return;
    };
    if entry.is_dir {
        app.status = "[-] Directories can only be encrypted or deleted.".to_owned();
        return;
    }
    let path = entry.path.clone();

    if let Some(info) = entry.info {
        if info.tar {
            app.status = "[-] This container holds a directory; decrypt it with [d].".to_owned();
            return;
        }
        app.start_dec(Pending::Open { source: path, editable }, Some(info));
        return;
    }

    match fs::read_to_string(&path) {
        Ok(content) => {
            app.set_text(&content);
            if editable {
                app.pending = Some(Pending::EncryptBuffer {
                    destination: crypto::enc_name(&path),
                    shred_after: Some(path),
                });
                app.mode = Mode::Compose;
                app.status = "Editing plaintext. Esc encrypts the result.".to_owned();
            } else {
                app.mode = Mode::Viewing;
                app.status = "Read-only view. Esc returns.".to_owned();
            }
        }
        Err(_) => app.status = "[-] Not a readable text file.".to_owned(),
    }
}

fn command(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            let target = expand_path(&app.command_input);
            app.command_input.clear();
            if target.as_os_str().is_empty() {
                app.reset();
                app.status = "Import cancelled.".to_owned();
                return;
            }
            if !target.exists() {
                app.mode = Mode::Normal;
                app.status = format!("[-] Not found: {}", target.display());
                return;
            }
            app.start_enc(Pending::EncryptPath { source: target });
        }
        KeyCode::Esc => {
            app.reset();
            app.status = "Import cancelled.".to_owned();
        }
        KeyCode::Backspace => {
            app.command_input.pop();
        }
        KeyCode::Char(c) => app.command_input.push(c),
        _ => {}
    }
}

fn new_name(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => {
            let name = app.filename_input.trim().to_owned();
            if name.is_empty() {
                app.status = "[-] The name cannot be empty.".to_owned();
                return;
            }
            match workspace::enc_in_ws(&name) {
                Ok(destination) if destination.exists() => {
                    app.status = format!("[-] {} already exists.", fname(&destination));
                }
                Ok(_) => {
                    app.pending = Some(Pending::CreateFile { name });
                    app.mode = Mode::Compose;
                    app.status = "Type the contents. Esc continues to encryption.".to_owned();
                }
                Err(err) => app.status = format!("[-] {err}"),
            }
        }
        KeyCode::Esc => {
            app.reset();
            app.status = "Cancelled.".to_owned();
        }
        KeyCode::Backspace => {
            app.filename_input.pop();
        }
        KeyCode::Char(c) => app.filename_input.push(c),
        _ => {}
    }
}

fn compose(app: &mut App, key: KeyEvent) {
    if key.code == KeyCode::Esc {
        let Some(pending) = app.pending.take() else {
            app.reset();
            return;
        };
        app.start_enc(pending);
        return;
    }
    app.textarea.input(key);
}

fn password(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => app.got_pass(),
        KeyCode::Esc => {
            app.reset();
            app.status = "Cancelled.".to_owned();
        }
        KeyCode::Backspace => app.password.pop(),
        KeyCode::Char(c) => app.password.push(c),
        _ => {}
    }
}

fn pass2(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter => app.got_pass2(),
        KeyCode::Esc => {
            app.reset();
            app.status = "Cancelled.".to_owned();
        }
        KeyCode::Backspace => app.confirmation.pop(),
        KeyCode::Char(c) => app.confirmation.push(c),
        _ => {}
    }
}

fn editing(app: &mut App, key: KeyEvent) {
    if key.code == KeyCode::Esc {
        app.save();
        return;
    }
    app.textarea.input(key);
}

fn viewing(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.reset();
            app.status = "View closed and buffer cleared.".to_owned();
        }
        KeyCode::Up
        | KeyCode::Down
        | KeyCode::Left
        | KeyCode::Right
        | KeyCode::PageUp
        | KeyCode::PageDown
        | KeyCode::Home
        | KeyCode::End => {
            app.textarea.input(key);
        }
        _ => {}
    }
}

fn docs(app: &mut App, key: KeyEvent) {
    if matches!(key.code, KeyCode::Esc | KeyCode::Char('i') | KeyCode::Char('q')) {
        app.mode = Mode::Normal;
        app.status = IDLE_HINT.to_owned();
    }
}

fn ask_hwid(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => app.set_hwid(true),
        KeyCode::Char('n') | KeyCode::Char('N') => app.set_hwid(false),
        KeyCode::Esc => {
            app.reset();
            app.status = "Cancelled.".to_owned();
        }
        _ => {}
    }
}

fn ask_shred(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => app.set_shred(true),
        KeyCode::Char('n') | KeyCode::Char('N') => app.set_shred(false),
        KeyCode::Esc => {
            app.reset();
            app.status = "Cancelled.".to_owned();
        }
        _ => {}
    }
}

fn ask_old_hwid(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => app.set_old_hwid(true),
        KeyCode::Char('n') | KeyCode::Char('N') => app.set_old_hwid(false),
        KeyCode::Esc => {
            app.reset();
            app.status = "Cancelled.".to_owned();
        }
        _ => {}
    }
}

fn ask_del(app: &mut App, key: KeyEvent) {
    let Some(path) = app.cur_path().map(Path::to_path_buf) else {
        app.reset();
        return;
    };
    match key.code {
        KeyCode::Char('s') | KeyCode::Char('S') => {
            app.status = match shred::shred(&path) {
                Ok(()) => format!("[!] Overwritten and deleted: {}", fname(&path)),
                Err(err) => format!("[-] {err}"),
            };
            app.mode = Mode::Normal;
            app.reload();
        }
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            let removed =
                if path.is_dir() { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
            app.status = match removed {
                Ok(()) => format!("[-] Deleted: {}", fname(&path)),
                Err(err) => format!("[-] {err}"),
            };
            app.mode = Mode::Normal;
            app.reload();
        }
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.mode = Mode::Normal;
            app.status = "Deletion cancelled.".to_owned();
        }
        _ => {}
    }
}

pub fn expand_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim().trim_matches('\'').trim_matches('"').trim();
    if trimmed.is_empty() {
        return PathBuf::new();
    }
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(trimmed)
}
