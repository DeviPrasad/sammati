use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum Choice {
    #[serde(rename = "prohibited")]
    Prohibited,
    #[serde(rename = "optional")]
    Optional,
    #[serde(rename = "recommended")]
    Recommended,
    #[serde(rename = "required")]
    #[default]
    Required,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub enum DefaultChoice<T> {
    #[serde(rename = "prohibited")]
    Prohibited,
    #[serde(rename = "optional")]
    Optional,
    #[serde(rename = "recommended")]
    Recommended,
    #[default]
    #[serde(rename = "required")]
    Required,
    #[serde(rename = "val")]
    Val(T),
}
