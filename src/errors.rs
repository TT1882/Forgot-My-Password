use anyhow::Error;
use std::process::exit;

pub fn exit_gracefully(e: Error) {
    eprintln!("Error: {}", e);
    e.chain()
        .skip(1)
        .for_each(|cause| eprintln!("because: {}", cause));
    exit(1);
}
