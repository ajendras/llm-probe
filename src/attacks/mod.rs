//! Built-in attack registry for LLM Probe.
//!
//! Aggregates prompt injection, jailbreak, encoding, and extraction attacks.
//! `all_attacks()` is the canonical list used by `RedTeamer` when the user
//! does not supply a custom set. The library ships with >15 distinct templates
//! and is designed to be extended via the `Attack` trait or YAML.

pub mod injection;
pub mod jailbreak;
pub mod extraction;

use crate::Attack;

/// Returns every built-in attack.
///
/// New attacks must be registered here (or returned by one of the submodule
/// `all_attacks()` helpers) so they appear in default scans and in the
/// interactive category filter.
pub fn all_attacks() -> Vec<Box<dyn Attack>> {
    let mut attacks = Vec::with_capacity(20);

    attacks.extend(injection::all_attacks());
    attacks.extend(jailbreak::all_attacks());
    // extraction::all_attacks() will be added when the module is implemented

    attacks
}
