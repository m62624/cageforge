// SPDX-License-Identifier: Apache-2.0

//! Conversion from private TOML values to validated public model values.
//!
//! The builders are reached through [`crate::Config::resolve`]. They keep raw
//! serde data private and delegate policy and command invariants to
//! `cageforge-policy` and `cageforge-command`.

mod command;
mod policy;

pub(crate) use command::build_command;
pub(crate) use policy::build_policy;
