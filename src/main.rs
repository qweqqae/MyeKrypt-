mod cli;
mod tui;

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    let outcome = if args.is_empty() { tui::run() } else { cli::run(&args) };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("cmf: {err}");
            ExitCode::FAILURE
        }
    }
}
