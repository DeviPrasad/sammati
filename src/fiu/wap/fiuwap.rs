#![allow(dead_code)]

use common::mutter;

#[tokio::main]
async fn main() {
    mutter::init_log();
    log::info!("FIU web app proxy started.");
}
