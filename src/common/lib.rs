#![forbid(unsafe_code)]

pub mod aa;
pub mod cfg;
pub mod choice;
pub mod ecdhe;
pub mod fip;
pub mod fiu;
pub mod hs;
pub mod keystore;
pub mod mutter;
pub mod ts;
pub mod types;

use crate::mutter::Mutter;
pub use cfg::Config;
use clap::Parser;
pub use log::{error, info};

#[derive(Debug, clap::Parser)]
#[clap(author, version, about, long_about = None)]
pub struct CommandlineArgs {
    #[clap(long, value_parser)]
    config: Option<String>,
}

#[allow(dead_code)]
impl CommandlineArgs {
    pub fn config() -> Result<Config, Mutter> {
        let cmd: CommandlineArgs = CommandlineArgs::parse();
        info!("Commandline arg: {:#?}", cmd);
        if let Some(path) = cmd.config {
            Config::from_path_str(&path)
        } else {
            error!("Error - configuration discovery parameter is missing.");
            Err(Mutter::MissingConfigParameters)
        }
    }
}
