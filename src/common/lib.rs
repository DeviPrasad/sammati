#![forbid(unsafe_code)]

mod cfg;
mod choice;
pub mod ets;
pub mod logger;
mod mutter;
pub mod resp;
pub mod types;

use crate::mutter::Mutter;
use cfg::Config;
use clap::Parser;
use log::{error, info};

#[derive(Debug, clap::Parser)]
#[clap(author, version, about, long_about = None)]
struct CommandlineArgs {
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
            error!("Error - PKCE configuration discovery parameter is missing.");
            Err(Mutter::MissingConfigParameters)
        }
    }
}
