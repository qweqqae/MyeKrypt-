use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use myekrypt::crypto::{self, EncryptOptions};
use myekrypt::format::ContainerInfo;
use myekrypt::{fsutil, shred, workspace, Secret};
use ratatui::widgets::ListState;
use tui_textarea::TextArea;
use zeroize::{Zeroize, Zeroizing};

use super::job::{Job, Outcome};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Mode {
    Normal,
    Command,
    NewFileName,
    Compose,
    Password,
    PasswordConfirm,
    Editing,
    Viewing,
    Documentation,
    AskDeviceLock,
    AskShred,
    AskLegacyDeviceLock,
    AskDelete,
}
pub enum Pending {
    EncryptPath { source: PathBuf },
    EncryptBuffer { destination: PathBuf, shred_after: Option<PathBuf> },
    CreateFile { name: String },
    Decrypt { source: PathBuf },
    Open { source: PathBuf, editable: bool },
}

impl Pending {
    fn can_shred(&self) -> Option<&Path> {
        match self {
            Pending::EncryptPath { source } => Some(source),
            Pending::EncryptBuffer { shred_after, .. } => shred_after.as_deref(),
            _ => None,
        }
    }
    fn is_enc(&self) -> bool {
        matches!(
            self,
            Pending::EncryptPath { .. } | Pending::EncryptBuffer { .. } | Pending::CreateFile { .. }
        )
    }
}
pub struct EditTarget {
    pub path: PathBuf,
    pub hwid: bool,
}

pub struct Entry {
    pub path: PathBuf,
    pub is_dir: bool,
    pub info: Option<ContainerInfo>,
}

impl Entry {
    fn from_path(path: PathBuf) -> Entry {
        let is_dir = path.is_dir();
        let info = if is_dir { None } else { crypto::peek(&path) };
        Entry { path, is_dir, info }
    }

    pub fn name(&self) -> String {
        fname(&self.path)
    }
}

pub struct App {
    pub files: Vec<Entry>,
    pub list_state: ListState,
    pub status: String,
    pub mode: Mode,
    pub password: Secret,
    pub confirmation: Secret,
    pub filename_input: String,
    pub command_input: String,
    pub textarea: TextArea<'static>,
    pub pending: Option<Pending>,
    pub edit_target: Option<EditTarget>,
    pub op_hwid: bool,
    pub op_shred: bool,
    pub legacy_hint: Option<bool>,
    pub job: Option<Job>,
    pub should_quit: bool,
    session_password: Secret,
}

pub const IDLE_HINT: &str =
    " [z] Import  [m] Edit  [v] Read  [n] New  [e] Encrypt  [d] Decrypt  [x] Delete  [i] Help  [q] Quit";

impl App {
    pub fn new() -> App {
        let mut app = App {
            files: Vec::new(),
            list_state: ListState::default(),
            status: IDLE_HINT.to_owned(),
            mode: Mode::Normal,
            password: Secret::new(),
            confirmation: Secret::new(),
            filename_input: String::new(),
            command_input: String::new(),
            textarea: TextArea::default(),
            pending: None,
            edit_target: None,
            op_hwid: false,
            op_shred: false,
            legacy_hint: None,
            job: None,
            should_quit: false,
            session_password: Secret::new(),
        };
        app.reload();
        app
    }

    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    pub fn reload(&mut self) {
        let mut paths: Vec<PathBuf> = fs::read_dir(workspace::root())
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|path| !hidden(path))
                    .collect()
            })
            .unwrap_or_default();
        paths.sort();
        self.files = paths.into_iter().map(Entry::from_path).collect();

        match self.list_state.selected() {
            _ if self.files.is_empty() => self.list_state.select(None),
            Some(index) if index < self.files.len() => {}
            _ => self.list_state.select(Some(0)),
        }
    }

    pub fn next(&mut self) {
        if self.files.is_empty() {
            return;
        }
        let index = match self.list_state.selected() {
            Some(current) if current + 1 < self.files.len() => current + 1,
            Some(_) => 0,
            None => 0,
        };
        self.list_state.select(Some(index));
    }

    pub fn previous(&mut self) {
        if self.files.is_empty() {
            return;
        }
        let index = match self.list_state.selected() {
            Some(0) | None => self.files.len() - 1,
            Some(current) => current - 1,
        };
        self.list_state.select(Some(index));
    }

    pub fn cur(&self) -> Option<&Entry> {
        self.list_state.selected().and_then(|index| self.files.get(index))
    }

    pub fn cur_path(&self) -> Option<&Path> {
        self.cur().map(|entry| entry.path.as_path())
    }
    pub fn reset(&mut self) {
        self.mode = Mode::Normal;
        self.pending = None;
        self.edit_target = None;
        self.op_hwid = false;
        self.op_shred = false;
        self.legacy_hint = None;
        self.password.clear();
        self.confirmation.clear();
        self.session_password.clear();
        self.filename_input.clear();
        self.command_input.clear();
        self.wipe_buf();
    }

    pub fn wipe_buf(&mut self) {
        let mut lines = std::mem::take(&mut self.textarea).into_lines();
        for line in &mut lines {
            line.zeroize();
        }
    }

    fn take_text(&mut self) -> Zeroizing<String> {
        let lines = std::mem::take(&mut self.textarea).into_lines();
        let text = Zeroizing::new(lines.join("\n"));
        let mut lines = lines;
        for line in &mut lines {
            line.zeroize();
        }
        text
    }
    pub fn set_text(&mut self, text: &str) {
        self.wipe_buf();
        self.textarea = TextArea::new(text.lines().map(str::to_owned).collect());
    }
    pub fn start_enc(&mut self, pending: Pending) {
        self.pending = Some(pending);
        self.op_hwid = false;
        self.op_shred = false;
        self.mode = Mode::AskDeviceLock;
        self.status = "[1/3] Bind to this device only? [y/n]  (Esc cancels)".to_owned();
    }

    pub fn set_hwid(&mut self, bind: bool) {
        self.op_hwid = bind;
        let has_source = self.pending.as_ref().and_then(Pending::can_shred).is_some();
        if has_source {
            self.mode = Mode::AskShred;
            self.status = "[2/3] Destroy the original after encrypting? [y/n]".to_owned();
        } else {
            self.ask_pass();
        }
    }

    pub fn set_shred(&mut self, shred_source: bool) {
        self.op_shred = shred_source;
        self.ask_pass();
    }
    pub fn start_dec(&mut self, pending: Pending, info: Option<ContainerInfo>) {
        self.pending = Some(pending);
        self.legacy_hint = None;
        match info.and_then(|info| info.hwid) {
            Some(_) => self.ask_pass(),
            None => {
                self.mode = Mode::AskLegacyDeviceLock;
                self.status =
                    "This container predates device flags. Was it bound to this device? [y/n]"
                        .to_owned();
            }
        }
    }

    pub fn set_old_hwid(&mut self, bound: bool) {
        self.legacy_hint = Some(bound);
        self.ask_pass();
    }

    fn ask_pass(&mut self) {
        self.password.clear();
        self.confirmation.clear();
        self.mode = Mode::Password;
        self.status = match self.pending.as_ref().map(Pending::is_enc) {
            Some(true) => "[3/3] New password (typed twice):".to_owned(),
            _ => "Password:".to_owned(),
        };
    }

    pub fn got_pass(&mut self) {
        let encrypting = self.pending.as_ref().map(Pending::is_enc).unwrap_or(false);
        if !encrypting {
            self.go();
            return;
        }
        if let Err(err) = crypto::check_pass(self.password.as_str()) {
            self.status = format!("[-] {err}");
            self.password.clear();
            return;
        }
        self.confirmation.clear();
        self.mode = Mode::PasswordConfirm;
        self.status = "Repeat the password:".to_owned();
    }

    pub fn got_pass2(&mut self) {
        if self.password.matches(&self.confirmation) {
            self.confirmation.clear();
            self.go();
        } else {
            self.password.clear();
            self.confirmation.clear();
            self.mode = Mode::Password;
            self.status = "[-] Passwords did not match. Start again:".to_owned();
        }
    }

    fn go(&mut self) {
        let Some(pending) = self.pending.take() else {
            self.reset();
            return;
        };

        let password = self.password.clone_z();
        let hwid = self.op_hwid;
        let shred_source = self.op_shred;
        let hint = self.legacy_hint;

        let job = match pending {
            Pending::EncryptPath { source } => {
                let label = fname(&source);
                let options = EncryptOptions { hwid, shred_source, overwrite: false };
                Job::spawn(format!("Encrypting {label}"), move |progress| {
                    let destination = enc_out(&source)?;
                    crypto::encrypt_file(&source, &destination, &password, options, progress)
                        .map(|written| Outcome::Message(format!("[+] Encrypted to {}", fname(&written))))
                        .map_err(|err| err.to_string())
                })
            }

            Pending::EncryptBuffer { destination, shred_after } => {
                let text = self.take_text();
                let options = EncryptOptions { hwid, shred_source: false, overwrite: false };
                let shred_after = if shred_source { shred_after } else { None };
                Job::spawn(format!("Encrypting {}", fname(&destination)), move |progress| {
                    let destination = fsutil::unused_path(&destination);
                    crypto::encrypt_buf(text.as_bytes(), &destination, &password, options, progress)
                        .map_err(|err| err.to_string())?;
                    if let Some(original) = shred_after {
                        shred::shred(&original).map_err(|err| err.to_string())?;
                    }
                    Ok(Outcome::Message(format!("[+] Encrypted to {}", fname(&destination))))
                })
            }

            Pending::CreateFile { name } => {
                let text = self.take_text();
                let options = EncryptOptions { hwid, shred_source: false, overwrite: false };
                Job::spawn(format!("Creating {name}"), move |progress| {
                    let destination = workspace::enc_in_ws(&name)
                        .map_err(|err| err.to_string())?;
                    if destination.exists() {
                        return Err(format!("{} already exists", fname(&destination)));
                    }
                    crypto::encrypt_buf(text.as_bytes(), &destination, &password, options, progress)
                        .map(|written| Outcome::Message(format!("[+] Created {}", fname(&written))))
                        .map_err(|err| err.to_string())
                })
            }

            Pending::Decrypt { source } => {
                let label = fname(&source);
                Job::spawn(format!("Decrypting {label}"), move |progress| {
                    crypto::decrypt(&source, workspace::root(), &password, hint, progress)
                        .map(|written| Outcome::Message(format!("[+] Restored {}", fname(&written))))
                        .map_err(|err| err.to_string())
                })
            }

            Pending::Open { source, editable } => {
                if editable {
                    self.session_password = Secret::from(self.password.as_str());
                    self.edit_target = Some(EditTarget {
                        path: source.clone(),
                        hwid: crypto::peek(&source).and_then(|info| info.hwid).unwrap_or(hwid),
                    });
                }
                let label = fname(&source);
                Job::spawn(format!("Opening {label}"), move |progress| {
                    crypto::decrypt_text(&source, &password, hint, progress)
                        .map(|text| Outcome::Opened { text, editable })
                        .map_err(|err| err.to_string())
                })
            }
        };

        self.password.clear();
        self.confirmation.clear();
        self.mode = Mode::Normal;
        self.job = Some(job);
    }
    pub fn save(&mut self) {
        let Some(target) = self.edit_target.as_ref() else {
            self.status = "[-] Nothing to save.".to_owned();
            self.reset();
            return;
        };
        if self.session_password.is_empty() {
            self.status = "[-] Editing session expired; nothing was saved.".to_owned();
            self.reset();
            return;
        }

        let options = EncryptOptions { hwid: target.hwid, shred_source: false, overwrite: true };
        let path = target.path.clone();
        let label = fname(&path);
        let password = self.session_password.clone_z();
        let text = self.take_text();

        self.mode = Mode::Normal;
        self.job = Some(Job::spawn(format!("Saving {label}"), move |progress| {
            match crypto::encrypt_buf(text.as_bytes(), &path, &password, options, progress) {
                Ok(written) => Ok(Outcome::Message(format!("[+] Saved {}", fname(&written)))),
                Err(err) => Ok(Outcome::SaveFailed { text, message: err.to_string() }),
            }
        }));
    }

    pub fn check_job(&mut self) {
        let Some(job) = self.job.as_ref() else {
            return;
        };
        let Some(outcome) = job.poll() else {
            return;
        };
        self.job = None;

        match outcome {
            Ok(Outcome::Message(message)) => {
                self.reset();
                self.status = message;
                self.reload();
            }
            Ok(Outcome::Opened { text, editable }) => {
                self.set_text(&text);
                if editable {
                    self.mode = Mode::Editing;
                    self.status = "Editing in memory. Esc saves and re-encrypts.".to_owned();
                } else {
                    self.mode = Mode::Viewing;
                    self.status = "Read-only view in memory. Esc discards it.".to_owned();
                }
            }
            Ok(Outcome::SaveFailed { text, message }) => {
                self.set_text(&text);
                self.mode = Mode::Editing;
                self.status = format!("[-] {message} - your changes are still open here.");
            }
            Err(message) => {
                self.reset();
                self.status = format!("[-] {message}");
            }
        }
    }
    pub fn details(&self) -> Details {
        let Some(entry) = self.cur() else {
            return Details::empty();
        };
        let Ok(meta) = fs::metadata(&entry.path) else {
            return Details::empty();
        };

        let kind = match entry.info {
            _ if entry.is_dir => "Directory".to_owned(),
            Some(info) if info.tar => format!("Encrypted directory (v{})", info.version),
            Some(info) => format!("Encrypted file (v{})", info.version),
            None => "Plaintext".to_owned(),
        };

        let binding = match entry.info.map(|info| info.hwid) {
            Some(Some(true)) => "Yes - bound to this machine".to_owned(),
            Some(Some(false)) => "No - any machine".to_owned(),
            Some(None) => "Unknown - container predates the flag".to_owned(),
            None => "-".to_owned(),
        };

        Details {
            name: entry.name(),
            size: if entry.is_dir {
                fmt_size(fsutil::dir_size(&entry.path))
            } else {
                fmt_size(meta.len())
            },
            created: meta
                .created()
                .ok()
                .map(fmt_time)
                .unwrap_or_else(|| "Unknown".to_owned()),
            kind,
            binding,
        }
    }
}

pub struct Details {
    pub name: String,
    pub size: String,
    pub created: String,
    pub kind: String,
    pub binding: String,
}

impl Details {
    fn empty() -> Details {
        Details {
            name: "No selection".to_owned(),
            size: "-".to_owned(),
            created: "-".to_owned(),
            kind: "-".to_owned(),
            binding: "-".to_owned(),
        }
    }
}
fn enc_out(source: &Path) -> Result<PathBuf, String> {
    let name = source
        .file_name()
        .ok_or_else(|| format!("{} has no file name", source.display()))?
        .to_string_lossy()
        .into_owned();
    let destination = workspace::enc_in_ws(&name).map_err(|err| err.to_string())?;
    Ok(fsutil::unused_path(&destination))
}

pub fn fname(path: &Path) -> String {
    path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string())
}

fn hidden(path: &Path) -> bool {
    path.file_name()
        .map(|name| name.to_string_lossy().starts_with('.'))
        .unwrap_or(false)
}

fn fmt_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let value = bytes as f64;
    if value < KIB {
        format!("{bytes} B")
    } else if value < MIB {
        format!("{:.1} KiB", value / KIB)
    } else if value < GIB {
        format!("{:.1} MiB", value / MIB)
    } else {
        format!("{:.2} GiB", value / GIB)
    }
}
fn fmt_time(time: SystemTime) -> String {
    let seconds = time.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = (seconds / 86_400) as i64;
    let time_of_day = seconds % 86_400;

    let shifted = days + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = month_index + if month_index < 10 { 3 } else { -9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        time_of_day / 3600,
        (time_of_day % 3600) / 60
    )
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use myekrypt::Progress;

    use super::*;

    const PASSWORD: &str = "a decent passphrase";

    fn type_pass(app: &mut App, text: &str) {
        for c in text.chars() {
            app.password.push(c);
        }
    }

    fn type_pass2(app: &mut App, text: &str) {
        for c in text.chars() {
            app.confirmation.push(c);
        }
    }
    fn wait_job(app: &mut App) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while app.busy() {
            app.check_job();
            assert!(Instant::now() < deadline, "the job never finished");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn seal(path: &Path, contents: &str) {
        let options = EncryptOptions { hwid: false, shred_source: false, overwrite: false };
        crypto::encrypt_buf(contents.as_bytes(), path, PASSWORD, options, &Progress::new())
            .expect("seal test container");
    }
    #[test]
    fn save_keeps_password() {
        let dir = tempfile::tempdir().expect("temp dir");
        let container = dir.path().join("notes.txt.enc");
        seal(&container, "original contents");

        let mut app = App::new();
        let info = crypto::peek(&container);
        app.start_dec(Pending::Open { source: container.clone(), editable: true }, info);
        assert_eq!(app.mode, Mode::Password);

        type_pass(&mut app, PASSWORD);
        app.got_pass();
        wait_job(&mut app);
        assert_eq!(app.mode, Mode::Editing, "status was: {}", app.status);

        app.set_text("edited contents");
        app.save();
        wait_job(&mut app);
        assert!(app.status.starts_with("[+]"), "status was: {}", app.status);

        let reopened = crypto::decrypt_text(&container, PASSWORD, None, &Progress::new())
            .expect("the original password must still open the container");
        assert_eq!(reopened.as_str(), "edited contents");

        let with_empty_password =
            crypto::decrypt_text(&container, "", None, &Progress::new());
        assert!(with_empty_password.is_err(), "the container opened with an empty password");
    }
    #[test]
    fn save_fail_keeps_text() {
        let dir = tempfile::tempdir().expect("temp dir");
        let container = dir.path().join("notes.txt.enc");
        seal(&container, "original contents");
        let mut app = App::new();
        let info = crypto::peek(&container);
        app.start_dec(Pending::Open { source: container.clone(), editable: true }, info);
        type_pass(&mut app, PASSWORD);
        app.got_pass();
        wait_job(&mut app);
        assert_eq!(app.mode, Mode::Editing);
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, b"not a directory").expect("write");
        app.edit_target =
            Some(EditTarget { path: blocker.join("nested").join("notes.enc"), hwid: false });
        app.set_text("work I would rather not lose");
        app.save();
        wait_job(&mut app);
        assert_eq!(app.mode, Mode::Editing, "status was: {}", app.status);
        assert_eq!(app.textarea.lines(), ["work I would rather not lose"]);
        assert!(app.status.starts_with("[-]"), "status was: {}", app.status);
    }

    #[test]
    fn view_no_pass() {
        let dir = tempfile::tempdir().expect("temp dir");
        let container = dir.path().join("readonly.txt.enc");
        seal(&container, "just looking");

        let mut app = App::new();
        let info = crypto::peek(&container);
        app.start_dec(Pending::Open { source: container.clone(), editable: false }, info);
        type_pass(&mut app, PASSWORD);
        app.got_pass();
        wait_job(&mut app);

        assert_eq!(app.mode, Mode::Viewing, "status was: {}", app.status);
        assert!(app.session_password.is_empty());
        assert!(app.edit_target.is_none());
    }

    #[test]
    fn encrypt_asks_twice() {
        let mut app = App::new();
        app.start_enc(Pending::CreateFile { name: "draft".to_owned() });
        assert_eq!(app.mode, Mode::AskDeviceLock);

        app.set_hwid(false);
        assert_eq!(app.mode, Mode::Password);

        type_pass(&mut app, PASSWORD);
        app.got_pass();
        assert_eq!(app.mode, Mode::PasswordConfirm);

        type_pass2(&mut app, "something else entirely");
        app.got_pass2();
        assert_eq!(app.mode, Mode::Password, "a mismatch must not start the job");
        assert!(!app.busy());
        assert!(app.password.is_empty());
        assert!(app.confirmation.is_empty());
    }

    #[test]
    fn shred_only_on_encrypt() {
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("plain.txt");
        fs::write(&source, b"content").expect("write");

        let mut app = App::new();
        app.start_enc(Pending::EncryptPath { source });
        app.set_hwid(false);
        assert_eq!(app.mode, Mode::AskShred);
    }

    #[test]
    fn short_pass_blocked() {
        let mut app = App::new();
        app.start_enc(Pending::CreateFile { name: "draft".to_owned() });
        app.set_hwid(false);

        type_pass(&mut app, "short");
        app.got_pass();

        assert_eq!(app.mode, Mode::Password);
        assert!(app.status.starts_with("[-]"), "status was: {}", app.status);
        assert!(app.password.is_empty());
    }
    #[test]
    fn short_pass_ok_on_open() {
        let mut app = App::new();
        let info = myekrypt::format::ContainerInfo { version: 2, hwid: Some(false), tar: false };
        app.start_dec(
            Pending::Decrypt { source: PathBuf::from("missing.enc") },
            Some(info),
        );
        type_pass(&mut app, "x");
        app.got_pass();
        assert_ne!(app.mode, Mode::PasswordConfirm);
        wait_job(&mut app);
        assert!(app.status.starts_with("[-]"));
    }

    #[test]
    fn reset_wipes_stuff() {
        let mut app = App::new();
        type_pass(&mut app, "a password");
        type_pass2(&mut app, "a password");
        app.set_text("decrypted content");
        app.filename_input.push_str("draft");

        app.reset();

        assert!(app.password.is_empty());
        assert!(app.confirmation.is_empty());
        assert!(app.session_password.is_empty());
        assert!(app.filename_input.is_empty());
        assert_eq!(app.textarea.lines(), [""]);
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.pending.is_none());
    }
}
