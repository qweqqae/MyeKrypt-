use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use myekrypt::Progress;
use zeroize::Zeroizing;

pub enum Outcome {
    Message(String),
    Opened { text: Zeroizing<String>, editable: bool },
    SaveFailed { text: Zeroizing<String>, message: String },
}

pub struct Job {
    pub title: String,
    pub progress: Progress,
    receiver: Receiver<Result<Outcome, String>>,
}

impl Job {
    pub fn spawn<F>(title: impl Into<String>, work: F) -> Job
    where
        F: FnOnce(&Progress) -> Result<Outcome, String> + Send + 'static,
    {
        let progress = Progress::new();
        let (sender, receiver) = mpsc::channel();
        let worker_progress = progress.clone();
        thread::spawn(move || {
            let _ = sender.send(work(&worker_progress));
        });
        Job { title: title.into(), progress, receiver }
    }

    pub fn poll(&self) -> Option<Result<Outcome, String>> {
        match self.receiver.try_recv() {
            Ok(outcome) => Some(outcome),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                Some(Err("the worker thread stopped unexpectedly".to_owned()))
            }
        }
    }
}
