use crate::mutter::Mutter;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostConfig {
    pub scheme: String, // http, https
    pub name: String,   // "fip.sammati.web3pleb.org"
    pub port: u16,
    pub address: String, // "fip.sammati.web3pleb.org:40401"
    pub cert: String,
    pub key: String,
    pub url: String,
    pub cid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub host: HostConfig,
}

impl Config {
    pub fn from_path_str(path: &str) -> Result<Config, Mutter> {
        //log::debug!("from_path - {:#?}", path);
        let json: String = fs::read_to_string(path).map_err(|_e| {
            log::debug!("from_path - {:#?}", path);
            Mutter::BadConfigFilePath
        })?;

        //log::info!("from_path - {:#?}", json);
        serde_json::from_str::<Config>(&json).map_err(|e| {
            log::error!("serde error: {:#?}", e);
            Mutter::BadConfigJson
        })
    }
}

#[cfg(test)]
mod cfg {
    use crate::cfg::Config;
    use crate::mutter;
    use log::info;
    use std::path::PathBuf;

    #[test]
    fn test_001() {
        let rs = r#"{
            "host": {
                "scheme": "http",
                "name": "pygmy.web3pleb.org",
                "port": 40401,
                "address": "pygmy.web3pleb.org:40401",
                "cert": "sammati-self-signed.pem",
                "key": "sammati-key.pem",
                "url": "https://fip.sammati.in/",
                "cid": 100001
            }
        }"#;
        mutter::init_log();
        let cfg: Result<Config, _> = serde_json::from_str(rs);
        assert!(cfg.is_ok());
        info!("test_config_001 - {:#?}", cfg.unwrap());
    }
    #[test]
    fn test_002() {
        let pb: PathBuf = [
            env!("CARGO_MANIFEST_DIR"),
            "mock",
            "config",
            "fip-wap-cfg.json",
        ]
        .iter()
        .collect();
        let ps = pb.as_os_str().to_str().unwrap();
        let fip_cfg: Config = Config::from_path_str(ps).unwrap();
        let cfg = serde_json::to_string::<Config>(&fip_cfg);
        assert!(cfg.is_ok());
    }
}
