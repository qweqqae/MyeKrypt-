use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Gauge, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, Mode};

const ACCENT: Color = Color::Green;
const MUTED: Color = Color::DarkGray;
const WARN: Color = Color::Yellow;
const DANGER: Color = Color::Red;

const LOGO_HEIGHT: u16 = 11;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(frame.size());

    match app.mode {
        Mode::Compose | Mode::Editing | Mode::Viewing => draw_edit(frame, app, root[0]),
        Mode::Documentation => draw_help(frame, root[0]),
        _ => draw_main(frame, app, root[0]),
    }

    draw_stat(frame, app, root[1]);
}

fn logo() -> Vec<Line<'static>> {
    let bold = Style::default().fg(ACCENT).add_modifier(Modifier::BOLD);
    let plain = Style::default().fg(ACCENT);
    vec![
        Line::from(Span::styled("MyeKrypt", bold)),
        Line::from(""),
        Line::from(Span::styled("      ████      ", plain)),
        Line::from(Span::styled("    ████████    ", plain)),
        Line::from(Span::styled("   ████  ████   ", plain)),
        Line::from(Span::styled("  ████    ████  ", plain)),
        Line::from(Span::styled("  ████  ██████  ", plain)),
        Line::from(Span::styled("   ███████████  ", plain)),
        Line::from(Span::styled("    ████████    ", plain)),
        Line::from(Span::styled("      ████      ", plain)),
    ]
}

fn box_style(title: &str, color: Color) -> Block<'_> {
    Block::default()
        .title(format!(" {title} "))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
}

fn draw_edit(frame: &mut Frame, app: &mut App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(LOGO_HEIGHT), Constraint::Min(5)])
        .split(area);

    frame.render_widget(Paragraph::new(logo()).block(box_style("", MUTED)), rows[0]);

    let (title, color) = match app.mode {
        Mode::Compose => ("composing - Esc encrypts", ACCENT),
        Mode::Editing => ("editing in memory - Esc saves and re-encrypts", WARN),
        _ => ("read-only view in memory - Esc discards", Color::Cyan),
    };
    app.textarea.set_block(box_style(title, color));
    frame.render_widget(app.textarea.widget(), rows[1]);
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let text = "\
MyeKrypt - how it works and what it does not do

CRYPTOGRAPHY
  AES-256-GCM in chunks of 64 KiB using the STREAM construction, so a
  container is limited by free disk space rather than by memory, and
  truncating one is detected instead of silently returning short data.
  Keys come from Argon2id (64 MiB, 4 passes, 4 lanes). The salt and the
  cost parameters live in the header, and the whole header is
  authenticated, so editing it breaks the tag instead of changing how
  the container opens.

TRUSTED DEVICE BINDING - READ THIS
  Binding mixes the machine's hardware id into the key. A hardware id
  is NOT a secret: any process on the machine can read it and fleet
  management tools collect it. Binding makes a container useless if it
  is copied elsewhere; it does not protect it against someone using
  this machine. There is no recovery key, so a bound container is lost
  for good if the machine is replaced or reinstalled.

OVERWRITE AND DELETE - ALSO READ THIS
  [x][s] overwrites the file with random bytes, renames it and unlinks
  it. On SSDs, copy-on-write filesystems (APFS, Btrfs, ZFS) and
  anything with snapshots or backups, the previous contents can survive
  regardless. Full-disk encryption is what actually protects deleted
  files there.

KEYS
  z  import any path and encrypt it into the workspace
  n  create a new encrypted file
  v  read a container in memory, read-only
  m  edit a container in memory and re-seal it on exit
  e  encrypt the selected file or directory
  d  decrypt the selection back into the workspace
  x  delete the selection, with or without overwriting
  r  reload the workspace listing
  i  this page      q / Esc  quit

Esc, i or q returns to the workspace.";

    frame.render_widget(
        Paragraph::new(text)
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: false })
            .block(box_style("documentation", ACCENT)),
        area,
    );
}

fn draw_main(frame: &mut Frame, app: &mut App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(LOGO_HEIGHT), Constraint::Min(5)])
        .split(columns[0]);

    frame.render_widget(Paragraph::new(logo()).block(box_style("", MUTED)), left[0]);
    draw_files(frame, app, left[1]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Length(11), Constraint::Min(4)])
        .split(columns[1]);

    draw_info(frame, app, right[0]);
    draw_keys(frame, right[1]);
    draw_prompt(frame, app, right[2]);
}

fn draw_files(frame: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .files
        .iter()
        .map(|entry| {
            let (prefix, color) = match entry.info {
                _ if entry.is_dir => ("dir  ", Color::LightBlue),
                Some(info) if info.tar => ("arch ", WARN),
                Some(_) => ("enc  ", WARN),
                None => ("plain", Color::White),
            };
            ListItem::new(format!("{prefix} {}", entry.name()))
                .style(Style::default().fg(color))
        })
        .collect();

    let list = List::new(items)
        .block(box_style("workspace", ACCENT))
        .highlight_style(Style::default().bg(ACCENT).fg(Color::Black).add_modifier(Modifier::BOLD))
        .highlight_symbol(" > ");

    frame.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_info(frame: &mut Frame, app: &App, area: Rect) {
    let details = app.details();
    let label = Style::default().fg(MUTED);

    let binding_color = if details.binding.starts_with("Yes") {
        Color::LightGreen
    } else if details.binding.starts_with("Unknown") {
        WARN
    } else {
        Color::White
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("Name    ", label),
            Span::styled(details.name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Created ", label),
            Span::styled(details.created, Style::default().fg(ACCENT)),
        ]),
        Line::from(vec![
            Span::styled("Size    ", label),
            Span::styled(details.size, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("Format  ", label),
            Span::styled(details.kind, Style::default().fg(WARN)),
        ]),
        Line::from(vec![
            Span::styled("Device  ", label),
            Span::styled(details.binding, Style::default().fg(binding_color)),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines).block(box_style("selection", ACCENT)), area);
}

fn draw_keys(frame: &mut Frame, area: Rect) {
    let key = |k: &'static str, color: Color| Span::styled(format!(" {k} "), Style::default().fg(Color::Black).bg(color));
    let lines = vec![
        Line::from(vec![key("z", WARN), Span::raw(" Import a path and encrypt it")]),
        Line::from(""),
        Line::from(vec![key("m", ACCENT), Span::raw(" Edit in memory")]),
        Line::from(""),
        Line::from(vec![key("v", ACCENT), Span::raw(" Read in memory")]),
        Line::from(""),
        Line::from(vec![
            key("e", ACCENT),
            Span::raw(" Encrypt   "),
            key("d", ACCENT),
            Span::raw(" Decrypt   "),
            key("n", ACCENT),
            Span::raw(" New"),
        ]),
        Line::from(""),
        Line::from(vec![key("x", DANGER), Span::raw(" Delete   "), key("i", Color::Cyan), Span::raw(" Help   "), key("q", MUTED), Span::raw(" Quit")]),
    ];

    frame.render_widget(Paragraph::new(lines).block(box_style("operations", MUTED)), area);
}

fn draw_prompt(frame: &mut Frame, app: &App, area: Rect) {
    if let Some(job) = app.job.as_ref() {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(1), Constraint::Min(0)])
            .margin(1)
            .split(area);

        frame.render_widget(box_style("working", WARN), area);
        frame.render_widget(
            Paragraph::new(job.title.as_str()).style(Style::default().fg(Color::White)),
            rows[0],
        );

        let ratio = job.progress.ratio();
        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(ACCENT).bg(Color::Black))
            .ratio(ratio.unwrap_or(0.0))
            .label(match ratio {
                Some(value) => format!("{:.0}%", value * 100.0),
                None => "deriving key...".to_owned(),
            });
        frame.render_widget(gauge, rows[1]);
        return;
    }

    let prompt = match app.mode {
        Mode::Command => vec![Line::from(vec![
            Span::styled("path> ", Style::default().fg(WARN)),
            Span::raw(app.command_input.as_str()),
            Span::styled("_", Style::default().fg(WARN)),
        ])],
        Mode::NewFileName => vec![Line::from(vec![
            Span::styled("name> ", Style::default().fg(ACCENT)),
            Span::raw(app.filename_input.as_str()),
            Span::styled("_", Style::default().fg(ACCENT)),
        ])],
        Mode::Password => vec![
            Line::from(Span::styled(
                "password",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::raw("*".repeat(app.password.nchars()))),
        ],
        Mode::PasswordConfirm => vec![
            Line::from(Span::styled(
                "repeat password",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::raw("*".repeat(app.confirmation.nchars()))),
        ],
        Mode::AskDeviceLock => vec![
            Line::from(Span::styled(
                "Bind to this device? [y/n]",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "A bound container cannot be opened on another machine, and",
                Style::default().fg(MUTED),
            )),
            Line::from(Span::styled("there is no recovery key.", Style::default().fg(MUTED))),
        ],
        Mode::AskShred => vec![
            Line::from(Span::styled(
                "Destroy the original? [y/n]",
                Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "Only after the container is safely written.",
                Style::default().fg(MUTED),
            )),
        ],
        Mode::AskLegacyDeviceLock => vec![Line::from(Span::styled(
            "Was this container bound to this device? [y/n]",
            Style::default().fg(WARN).add_modifier(Modifier::BOLD),
        ))],
        Mode::AskDelete => vec![
            Line::from(Span::styled(
                "[s] overwrite and delete",
                Style::default().fg(DANGER).add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled("[y] just delete", Style::default().fg(DANGER))),
            Line::from(Span::styled("[Esc] cancel", Style::default().fg(MUTED))),
        ],
        _ => vec![
            Line::from(Span::styled("Workspace", Style::default().fg(MUTED))),
            Line::from(Span::styled(
                myekrypt::workspace::root().display().to_string(),
                Style::default().fg(Color::White),
            )),
        ],
    };

    frame.render_widget(Paragraph::new(prompt).wrap(Wrap { trim: false }).block(box_style("prompt", MUTED)), area);
}

fn draw_stat(frame: &mut Frame, app: &App, area: Rect) {
    let color = if app.status.starts_with("[-]") {
        DANGER
    } else if app.status.starts_with("[+]") {
        ACCENT
    } else if app.status.starts_with("[!]") {
        WARN
    } else {
        MUTED
    };

    frame.render_widget(
        Paragraph::new(app.status.as_str())
            .style(Style::default().fg(color))
            .wrap(Wrap { trim: true })
            .block(box_style("status", color)),
        area,
    );
}
