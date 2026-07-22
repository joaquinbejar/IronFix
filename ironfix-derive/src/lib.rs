/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Derive
//!
//! Procedural macros for the IronFix FIX protocol engine.
//!
//! This crate provides derive macros for automatic implementation of
//! FIX message encoding and decoding traits.
//!
//! ## Macros
//!
//! - `#[derive(FixMessage)]` - Implements the `FixMessage` trait
//! - `#[derive(FixField)]` - Implements the `FixField` trait

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

/// Derives the `FixMessage` trait for a struct.
///
/// # Attributes
///
/// - `#[fix(msg_type = "X")]` - Specifies the message type (tag 35 value)
///
/// # Example
///
/// ```ignore
/// #[derive(FixMessage)]
/// #[fix(msg_type = "D")]
/// pub struct NewOrderSingle {
///     #[fix(tag = 11)]
///     pub cl_ord_id: String,
///     #[fix(tag = 55)]
///     pub symbol: String,
/// }
/// ```
#[proc_macro_derive(FixMessage, attributes(fix))]
pub fn derive_fix_message(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Extract msg_type from attributes
    let msg_type = extract_msg_type(&input.attrs).unwrap_or_else(|| "0".to_string());

    let expanded = quote! {
        impl FixMessage for #name {
            const MSG_TYPE: &'static str = #msg_type;

            fn from_raw(raw: &RawMessage<'_>) -> Result<Self, DecodeError> {
                todo!("FixMessage::from_raw not yet implemented for {}", stringify!(#name))
            }

            fn encode(&self, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
                todo!("FixMessage::encode not yet implemented for {}", stringify!(#name))
            }
        }
    };

    TokenStream::from(expanded)
}

/// Derives the `FixField` trait for a type.
///
/// # Attributes
///
/// - `#[fix(tag = N)]` - Specifies the field tag number
///
/// # Example
///
/// ```ignore
/// #[derive(FixField)]
/// #[fix(tag = 54)]
/// pub struct Side(char);
/// ```
#[proc_macro_derive(FixField, attributes(fix))]
pub fn derive_fix_field(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Extract tag from attributes
    let tag = extract_tag(&input.attrs).unwrap_or(0);

    let expanded = quote! {
        impl FixField for #name {
            const TAG: u32 = #tag;
            type Value = Self;

            fn decode(bytes: &[u8]) -> Result<Self::Value, DecodeError> {
                todo!("FixField::decode not yet implemented for {}", stringify!(#name))
            }

            fn encode(value: &Self::Value, buf: &mut Vec<u8>) -> Result<(), EncodeError> {
                todo!("FixField::encode not yet implemented for {}", stringify!(#name))
            }
        }
    };

    TokenStream::from(expanded)
}

/// Extracts the msg_type value from attributes.
fn extract_msg_type(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path().is_ident("fix")
            && let Ok(meta) = attr.parse_args::<syn::Meta>()
            && let syn::Meta::NameValue(nv) = meta
            && nv.path.is_ident("msg_type")
            && let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(lit_str),
                ..
            }) = nv.value
        {
            return Some(lit_str.value());
        }
    }
    None
}

/// Extracts the tag value from attributes.
fn extract_tag(attrs: &[syn::Attribute]) -> Option<u32> {
    for attr in attrs {
        if attr.path().is_ident("fix")
            && let Ok(meta) = attr.parse_args::<syn::Meta>()
            && let syn::Meta::NameValue(nv) = meta
            && nv.path.is_ident("tag")
            && let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(lit_int),
                ..
            }) = nv.value
        {
            return lit_int.base10_parse().ok();
        }
    }
    None
}
