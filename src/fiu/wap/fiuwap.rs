use common::logger;

#[tokio::main]
async fn main() {
    logger::init();
    log::info!("FIU web app proxy started.");
}
