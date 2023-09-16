use common::logger;

#[tokio::main]
async fn main() {
    logger::init();
    log::info!("AA service started.");
}
