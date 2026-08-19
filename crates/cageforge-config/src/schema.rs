// SPDX-License-Identifier: Apache-2.0

//! JSON Schema generation for the private TOML model.
//!
//! [`crate::config_schema_json`] describes document structure for tooling; it
//! does not replace semantic validation performed by [`crate::Config`].

use crate::model::RawConfig;

/// Generates the JSON Schema for the Cageforge TOML data model.
///
/// JSON Schema describes the shape of the document for editor completion and
/// structural validation. Semantic checks such as inheritance cycles and
/// filesystem safety remain in [`crate::Config::from_toml`] and resolution.
fn config_schema() -> schemars::Schema {
    schemars::schema_for!(RawConfig)
}

/// Generates a pretty-printed JSON Schema document.
pub fn config_schema_json() -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&config_schema())
}
