pub mod injection;
pub mod jailbreak;

use crate::Attack;

/// Returns every built-in attack.
///
/// New attacks can be registered here by calling the appropriate
/// `xxx::XxxAttack::all_attacks()` helper so they appear in default scans
/// and in the interactive category filter.
///
/// For user-defined attacks without writing Rust, use
/// [`crate::load_attacks_from_yaml`] (or [`crate::parse_yaml_attacks`])
/// instead.
pub fn all_attacks() -> Vec<Box<dyn Attack>> {
    let mut attacks = Vec::with_capacity(20);

    attacks.extend(injection::PromptInjectionAttack::all_attacks());
    attacks.extend(jailbreak::JailbreakAttack::all_attacks());

    attacks
}
