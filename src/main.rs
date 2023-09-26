use common::mutter;

#[tokio::main]
async fn main() {
    mutter::init_log();
    log::info!("Sammati started.");
}
