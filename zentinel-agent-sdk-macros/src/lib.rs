//! Derive macros for zentinel-agent-sdk.
//!
//! This crate provides procedural macros for the Zentinel Agent SDK:
//! - `#[derive(AgentConfig)]` - Derive configuration handling for agents
//!
//! These macros are re-exported from `zentinel-agent-sdk` when the `macros` feature is enabled.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

/// Derive macro for agent configuration structs.
///
/// This generates:
/// - `from_config_json(value: serde_json::Value) -> Result<Self, String>` - Deserialize from JSON with kebab-case field names
/// - `config_fields() -> &'static [&'static str]` - List of config field names in kebab-case
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
///     max_retries: u32,
/// }
///
/// // Generated methods:
/// // MyConfig::from_config_json(value) -> Result<MyConfig, String>
/// // MyConfig::config_fields() -> &["enabled", "threshold", "max-retries"]
/// ```
#[proc_macro_derive(AgentConfig, attributes(config))]
pub fn derive_agent_config(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match impl_agent_config(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn to_kebab_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('-');
            }
            result.push(ch.to_lowercase().next().unwrap());
        } else if ch == '_' {
            result.push('-');
        } else {
            result.push(ch);
        }
    }
    result
}

fn impl_agent_config(
    input: &DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    name,
                    "AgentConfig can only be derived for structs with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                name,
                "AgentConfig can only be derived for structs",
            ));
        }
    };

    // Generate kebab-case field name literals
    let field_names_kebab: Vec<String> = fields
        .iter()
        .map(|f| to_kebab_case(&f.ident.as_ref().unwrap().to_string()))
        .collect();

    let field_name_literals: Vec<&str> = field_names_kebab.iter().map(|s| s.as_str()).collect();

    Ok(quote! {
        impl #name {
            /// Deserialize this config from a JSON value, using kebab-case field names.
            pub fn from_config_json(value: serde_json::Value) -> Result<Self, String> {
                // Use serde's rename_all = "kebab-case" via the struct's own Deserialize impl.
                // The struct should have #[serde(rename_all = "kebab-case")] applied.
                serde_json::from_value(value).map_err(|e| format!("Config parse error: {}", e))
            }

            /// Return the list of config field names in kebab-case.
            pub fn config_fields() -> &'static [&'static str] {
                &[#(#field_name_literals),*]
            }
        }
    })
}
