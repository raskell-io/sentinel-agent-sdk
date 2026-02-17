//! Derive macros for zentinel-agent-sdk.
//!
//! This crate provides procedural macros for the Zentinel Agent SDK:
//! - `#[derive(AgentConfig)]` - Derive configuration handling for agents
//!
//! These macros are re-exported from `zentinel-agent-sdk` when the `macros` feature is enabled.

use proc_macro::TokenStream;

/// Derive macro for agent configuration structs.
///
/// This adds automatic deserialization with kebab-case support
/// and default values.
///
/// # Example
///
/// ```ignore
/// use zentinel_agent_sdk_macros::AgentConfig;
///
/// #[derive(AgentConfig)]
/// struct MyConfig {
///     enabled: bool,
///     threshold: u32,
/// }
/// ```
#[proc_macro_derive(AgentConfig, attributes(config))]
pub fn derive_agent_config(_input: TokenStream) -> TokenStream {
    // Placeholder - will be implemented
    TokenStream::new()
}
