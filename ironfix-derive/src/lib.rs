/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! # IronFix Derive
//!
//! Procedural macros for the IronFix FIX protocol engine.
//!
//! This crate derives the two `ironfix-core` traits that give a Rust struct a
//! FIX wire form:
//!
//! - `#[derive(FixMessage)]` implements `ironfix_core::message::FixMessage`
//! - `#[derive(FixField)]` implements `ironfix_core::field::FixField`
//!
//! Both expansions name every type, trait, and enum variant by absolute path
//! (`::ironfix_core::…`, `::core::…`, `::std::…`), so a derived type compiles
//! in any module regardless of what that module has imported. The deriving
//! crate must depend on `ironfix-core`.
//!
//! ## What the derives guarantee
//!
//! - **Nothing is defaulted.** A missing or malformed `#[fix(...)]` attribute
//!   is a compile error naming what is missing. A MsgType is never assumed to
//!   be `0` (Heartbeat) and a tag is never assumed to be `0`.
//! - **Nothing panics.** The generated bodies return
//!   `DecodeError` / `EncodeError`; there is no `unwrap`,
//!   no indexing, and no `todo!()` in the expansion.
//!
//! ## `#[derive(FixMessage)]`
//!
//! Applies to a struct with **named fields**. The struct carries
//! `#[fix(msg_type = "D")]` and every field carries `#[fix(tag = N)]`.
//!
//! ```ignore
//! use ironfix_derive::FixMessage;
//! use rust_decimal::Decimal;
//!
//! #[derive(FixMessage)]
//! #[fix(msg_type = "D")]
//! pub struct NewOrderSingle {
//!     #[fix(tag = 11)]
//!     pub cl_ord_id: String,
//!     #[fix(tag = 55)]
//!     pub symbol: String,
//!     #[fix(tag = 44)]
//!     pub price: Option<Decimal>,
//! }
//! ```
//!
//! - `from_raw` first checks that the raw message's MsgType (tag 35) equals
//!   `MSG_TYPE`, so decoding an `ExecutionReport` as a `NewOrderSingle` is a
//!   typed error rather than a half-populated struct. A field typed `Option<T>`
//!   is optional; any other type is required and its absence is
//!   `DecodeError::MissingRequiredField`.
//! - `encode` appends `tag=value<SOH>` for each field **in declaration order**
//!   and writes nothing else: no BeginString (8), no BodyLength (9), no
//!   MsgType (35), no CheckSum (10). It produces the *body* fields, matching
//!   the convention of `ironfix_engine::OutboundMessage`, where the engine
//!   stamps the header and trailer. The output of `encode` is therefore **not
//!   a complete FIX message** and must not be written to a socket as one.
//!
//! ## `#[derive(FixField)]`
//!
//! Applies to a struct with exactly **one** field (a newtype or a one-field
//! named struct) carrying `#[fix(tag = N)]`.
//!
//! ```ignore
//! use ironfix_derive::FixField;
//!
//! #[derive(FixField)]
//! #[fix(tag = 11)]
//! pub struct ClOrdId(String);
//! ```
//!
//! `decode` converts the field's bytes into the inner type; `encode` appends
//! the complete `tag=value<SOH>` field, so concatenating derived fields yields
//! the same bytes as a derived `FixMessage` body.
//!
//! ## Supported field types
//!
//! The inner type is matched **syntactically** — the macro sees tokens, not
//! resolved types — and decides the wire conversion from the name:
//!
//! | Written type | Decode | Encode |
//! |---|---|---|
//! | `String` | UTF-8 validated | value bytes |
//! | `bool` | `Y`/`N` only | `Y` / `N` |
//! | `char` | single ASCII byte | that byte |
//! | `Vec<u8>` | raw bytes | raw bytes |
//! | anything else | [`FromStr`](std::str::FromStr) | [`Display`](std::fmt::Display) |
//!
//! So `Decimal`, `i64`, `u32`, and any user type implementing `FromStr` +
//! `Display` work through the last row. A type *aliased* to one of the named
//! rows (`type Symbol = String;`) takes the fallback path instead, because the
//! macro cannot resolve the alias.
//!
//! ## Limits, stated rather than hidden
//!
//! - **No repeating groups and no components.** A `Vec<T>` of anything but
//!   `u8` takes the fallback path and will not compile. Group-aware
//!   encoding/decoding is not implemented.
//! - **No `Length`/`Data` pairing.** A `Vec<u8>` field is written raw; if its
//!   bytes contain SOH, `encode` fails with
//!   `EncodeError::InvalidFieldValue`
//!   rather than emitting a frame that cannot be parsed back. Emitting the
//!   paired `Length` field is the caller's job.
//! - **No `skip`.** Every field of a derived `FixMessage` must map to a tag.
//! - **Nothing is validated against a dictionary.** These macros know only
//!   what the attributes say; conformance checking is
//!   `ironfix_dictionary::Validator`.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2, TokenTree};
use quote::{ToTokens, quote};
use std::collections::HashSet;
use syn::punctuated::Punctuated;
use syn::{
    Attribute, Data, DeriveInput, Expr, ExprLit, Fields, GenericArgument, Lit, LitInt, LitStr,
    Meta, PathArguments, Token, Type, WherePredicate, parse_macro_input, parse_quote,
};

/// The SOH byte (`0x01`) that terminates every field on the FIX wire.
const SOH: u8 = 0x01;

/// Longest accepted `msg_type` value, in bytes.
///
/// Mirrors `ironfix_core::message::MSG_TYPE_MAX_LEN`, which this crate cannot
/// import: a proc-macro crate has no internal dependencies. A longer value
/// could never equal a decoded MsgType, so rejecting it at expansion time turns
/// a message type that can never match into a compile error.
const MSG_TYPE_MAX_LEN: usize = 8;

/// Derives `ironfix_core::message::FixMessage` for a struct with named
/// fields.
///
/// # Attributes
///
/// - `#[fix(msg_type = "X")]` on the struct — **required**, the tag 35 value.
/// - `#[fix(tag = N)]` on every field — **required**, the field's FIX tag.
///
/// # Compile errors
///
/// Emitted, rather than a defaulted value, when: the struct attribute is
/// missing or is not a string literal; the value is empty, longer than
/// [`MSG_TYPE_MAX_LEN`] bytes, or carries a byte that cannot appear in tag 35;
/// the type is not a struct with named fields; a field has no `tag`; a tag is
/// `0`; or two fields declare the same tag.
///
/// # Example
///
/// ```ignore
/// #[derive(FixMessage)]
/// #[fix(msg_type = "D")]
/// pub struct NewOrderSingle {
///     #[fix(tag = 11)]
///     pub cl_ord_id: String,
///     #[fix(tag = 44)]
///     pub price: Option<rust_decimal::Decimal>,
/// }
/// ```
#[proc_macro_derive(FixMessage, attributes(fix))]
pub fn derive_fix_message(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_fix_message(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Derives `ironfix_core::field::FixField` for a single-field struct.
///
/// # Attributes
///
/// - `#[fix(tag = N)]` on the struct — **required**, the field's FIX tag.
///
/// # Compile errors
///
/// Emitted, rather than a defaulted tag, when: the attribute is missing or is
/// not an integer literal; the tag is `0`; the type is not a struct; the struct
/// does not have exactly one field; or the inner type is an `Option`, which has
/// no wire form of its own.
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
    expand_fix_field(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Builds the `FixMessage` implementation, or the error to report at the
/// derive site.
fn expand_fix_message(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;

    let metas = fix_metas(&input.attrs)?;
    reject_unknown_args(&metas, &["msg_type"])?;
    let msg_type = string_arg(&metas, "msg_type")?.ok_or_else(|| {
        syn::Error::new_spanned(
            name,
            "`#[derive(FixMessage)]` requires `#[fix(msg_type = \"...\")]`: the tag 35 value \
             is never defaulted",
        )
    })?;
    validate_msg_type(&msg_type)?;
    let msg_type_value = msg_type.value();

    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            name,
            "`#[derive(FixMessage)]` applies to a struct with named fields only",
        ));
    };
    let Fields::Named(named) = &data.fields else {
        return Err(syn::Error::new_spanned(
            name,
            "`#[derive(FixMessage)]` applies to a struct with named fields only: a field \
             needs a name to carry its `#[fix(tag = N)]`",
        ));
    };

    let mut seen: Vec<(u32, String)> = Vec::with_capacity(named.named.len());
    let mut decoders: Vec<TokenStream2> = Vec::with_capacity(named.named.len());
    let mut encoders: Vec<TokenStream2> = Vec::with_capacity(named.named.len());

    let type_params: Vec<String> = input
        .generics
        .type_params()
        .map(|param| param.ident.to_string())
        .collect();
    let mut bound_seen: HashSet<String> = HashSet::new();
    let mut extra_bounds: Vec<WherePredicate> = Vec::new();

    for field in &named.named {
        let Some(ident) = field.ident.as_ref() else {
            return Err(syn::Error::new_spanned(
                field,
                "every field of a derived FixMessage must be named",
            ));
        };

        let field_metas = fix_metas(&field.attrs)?;
        reject_unknown_args(&field_metas, &["tag"])?;
        let tag_lit = int_arg(&field_metas, "tag")?.ok_or_else(|| {
            syn::Error::new_spanned(
                field,
                format!(
                    "field `{ident}` needs `#[fix(tag = N)]`: a missing tag is never \
                     defaulted to 0"
                ),
            )
        })?;
        let tag = parse_tag(&tag_lit)?;

        if let Some((_, other)) = seen.iter().find(|(seen_tag, _)| *seen_tag == tag) {
            return Err(syn::Error::new_spanned(
                &tag_lit,
                format!(
                    "tag {tag} is already declared by field `{other}`: a duplicate tag makes \
                     decoding ambiguous"
                ),
            ));
        }
        seen.push((tag, ident.to_string()));

        // An `Option<T>` field encodes and decodes its inner `T`, so the bound
        // is on the inner type, matching the wire conversion below.
        let value_ty = option_inner(&field.ty).unwrap_or(&field.ty);
        collect_fallback_bound(value_ty, &type_params, &mut bound_seen, &mut extra_bounds);

        match option_inner(&field.ty) {
            Some(inner) => {
                let decode = decode_expr(inner);
                decoders.push(quote! {
                    #ident: match ::ironfix_core::message::RawMessage::get_field(__raw, #tag) {
                        ::core::option::Option::Some(__field) => {
                            ::core::option::Option::Some(#decode)
                        }
                        ::core::option::Option::None => ::core::option::Option::None,
                    },
                });
                let write = write_field(inner, tag);
                encoders.push(quote! {
                    if let ::core::option::Option::Some(__value) = &self.#ident {
                        #write
                    }
                });
            }
            None => {
                let decode = decode_expr(&field.ty);
                decoders.push(quote! {
                    #ident: {
                        let __field = ::ironfix_core::message::RawMessage::get_field(__raw, #tag)
                            .ok_or_else(|| {
                                ::ironfix_core::error::DecodeError::MissingRequiredField {
                                    tag: #tag,
                                }
                            })?;
                        #decode
                    },
                });
                let write = write_field(&field.ty, tag);
                encoders.push(quote! {
                    {
                        let __value = &self.#ident;
                        #write
                    }
                });
            }
        }
    }

    let generics = generics_with_bounds(&input.generics, extra_bounds);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics ::ironfix_core::message::FixMessage for #name #ty_generics
            #where_clause
        {
            const MSG_TYPE: &'static str = #msg_type_value;

            fn from_raw(
                __raw: &::ironfix_core::message::RawMessage<'_>,
            ) -> ::core::result::Result<Self, ::ironfix_core::error::DecodeError> {
                let __actual = ::ironfix_core::message::MsgType::as_str(
                    ::ironfix_core::message::RawMessage::msg_type(__raw),
                );
                if __actual != #msg_type_value {
                    return ::core::result::Result::Err(
                        ::ironfix_core::error::DecodeError::InvalidFieldValue {
                            tag: 35u32,
                            reason: ::std::format!(
                                "expected MsgType '{}', found '{}'",
                                #msg_type_value,
                                __actual,
                            ),
                        },
                    );
                }
                ::core::result::Result::Ok(Self { #(#decoders)* })
            }

            fn encode(
                &self,
                __buf: &mut ::std::vec::Vec<u8>,
            ) -> ::core::result::Result<(), ::ironfix_core::error::EncodeError> {
                #(#encoders)*
                ::core::result::Result::Ok(())
            }
        }
    })
}

/// Builds the `FixField` implementation, or the error to report at the derive
/// site.
fn expand_fix_field(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;

    let metas = fix_metas(&input.attrs)?;
    reject_unknown_args(&metas, &["tag"])?;
    let tag_lit = int_arg(&metas, "tag")?.ok_or_else(|| {
        syn::Error::new_spanned(
            name,
            "`#[derive(FixField)]` requires `#[fix(tag = N)]`: the tag is never defaulted to 0",
        )
    })?;
    let tag = parse_tag(&tag_lit)?;

    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            name,
            "`#[derive(FixField)]` applies to a struct wrapping exactly one value",
        ));
    };

    let (inner_ty, construct, access) = match &data.fields {
        Fields::Unnamed(unnamed) if unnamed.unnamed.len() == 1 => {
            let Some(field) = unnamed.unnamed.first() else {
                return Err(syn::Error::new_spanned(name, "expected one wrapped value"));
            };
            let index = syn::Index::from(0);
            (&field.ty, quote!(Self(__inner)), quote!(&__value.#index))
        }
        Fields::Named(named) if named.named.len() == 1 => {
            let Some(field) = named.named.first() else {
                return Err(syn::Error::new_spanned(name, "expected one wrapped value"));
            };
            let Some(ident) = field.ident.as_ref() else {
                return Err(syn::Error::new_spanned(field, "expected a named field"));
            };
            (
                &field.ty,
                quote!(Self { #ident: __inner }),
                quote!(&__value.#ident),
            )
        }
        other => {
            return Err(syn::Error::new_spanned(
                other,
                "`#[derive(FixField)]` applies to a struct with exactly one field: a FIX field \
                 carries exactly one value",
            ));
        }
    };

    if option_inner(inner_ty).is_some() {
        return Err(syn::Error::new_spanned(
            inner_ty,
            "the wrapped value must not be an `Option`: an absent FIX field is expressed by \
             omitting it, not by encoding `None`",
        ));
    }

    let decode = decode_expr(inner_ty);
    let write = write_field(inner_ty, tag);

    let type_params: Vec<String> = input
        .generics
        .type_params()
        .map(|param| param.ident.to_string())
        .collect();
    let mut bound_seen: HashSet<String> = HashSet::new();
    let mut extra_bounds: Vec<WherePredicate> = Vec::new();
    collect_fallback_bound(inner_ty, &type_params, &mut bound_seen, &mut extra_bounds);

    let generics = generics_with_bounds(&input.generics, extra_bounds);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics ::ironfix_core::field::FixField for #name #ty_generics
            #where_clause
        {
            const TAG: u32 = #tag;

            type Value = Self;

            fn decode(
                __bytes: &[u8],
            ) -> ::core::result::Result<Self::Value, ::ironfix_core::error::DecodeError> {
                let __owned = ::ironfix_core::field::FieldRef::new(#tag, __bytes);
                let __field = &__owned;
                let __inner = #decode;
                ::core::result::Result::Ok(#construct)
            }

            fn encode(
                __value: &Self::Value,
                __buf: &mut ::std::vec::Vec<u8>,
            ) -> ::core::result::Result<(), ::ironfix_core::error::EncodeError> {
                let __value = #access;
                #write
                ::core::result::Result::Ok(())
            }
        }
    })
}

/// How a Rust type maps to and from its FIX wire form.
///
/// Decided from the written tokens: the macro cannot resolve a type alias or a
/// re-export, so `type Symbol = String;` is [`ValueKind::Parsed`], not
/// [`ValueKind::Text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueKind {
    /// `String`: UTF-8 validated on decode, raw bytes on encode.
    Text,
    /// `bool`: the FIX `Y`/`N` codes, never `true`/`false`.
    Boolean,
    /// `char`: exactly one ASCII byte.
    Character,
    /// `Vec<u8>`: raw bytes, unframed by any `Length` field.
    Bytes,
    /// Anything else: [`FromStr`](std::str::FromStr) in,
    /// [`Display`](std::fmt::Display) out.
    Parsed,
}

/// Classifies `ty` by the name it is written under.
fn classify(ty: &Type) -> ValueKind {
    let Type::Path(path) = ty else {
        return ValueKind::Parsed;
    };
    if path.qself.is_some() {
        return ValueKind::Parsed;
    }
    let Some(segment) = path.path.segments.last() else {
        return ValueKind::Parsed;
    };

    if matches!(segment.arguments, PathArguments::None) {
        if segment.ident == "String" {
            return ValueKind::Text;
        }
        if segment.ident == "bool" {
            return ValueKind::Boolean;
        }
        if segment.ident == "char" {
            return ValueKind::Character;
        }
        return ValueKind::Parsed;
    }

    if segment.ident == "Vec"
        && let PathArguments::AngleBracketed(args) = &segment.arguments
        && args.args.len() == 1
        && let Some(GenericArgument::Type(Type::Path(inner))) = args.args.first()
        && inner.path.is_ident("u8")
    {
        return ValueKind::Bytes;
    }

    ValueKind::Parsed
}

/// Returns the `T` of an `Option<T>`, or `None` for any other type.
fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    let segment = path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    if args.args.len() != 1 {
        return None;
    }
    match args.args.first()? {
        GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

/// Returns true when `ty`, written out, names any of `params` — the deriving
/// struct's type parameters.
///
/// A proc-macro sees syntax, not resolved types, so this walks the type's
/// tokens and matches identifiers by name. A match means a generated body that
/// parses or formats this field acts on a generic parameter and so needs a
/// bound the user's own declaration may not carry.
fn type_uses_param(ty: &Type, params: &[String]) -> bool {
    fn walk(tokens: TokenStream2, params: &[String]) -> bool {
        tokens.into_iter().any(|tree| match tree {
            TokenTree::Ident(ident) => params.contains(&ident.to_string()),
            TokenTree::Group(group) => walk(group.stream(), params),
            _ => false,
        })
    }
    walk(ty.to_token_stream(), params)
}

/// Adds the `FromStr + Display` bound the fallback wire path needs for
/// `value_ty`, when that type is handled by the fallback and names a struct
/// type parameter.
///
/// The fallback decode calls `FieldRef::parse::<T>` (needs
/// [`FromStr`](std::str::FromStr)) and the fallback encode formats with `{}`
/// (needs [`Display`](std::fmt::Display)). A user who writes `struct Order<T:
/// Clone>` declares neither, so without this the generated impl would not
/// type-check. Bounds are added only for a type that names a parameter, so a
/// concrete field like `Decimal` gains no redundant where-clause. `seen`
/// dedupes identical predicates across fields.
fn collect_fallback_bound(
    value_ty: &Type,
    params: &[String],
    seen: &mut HashSet<String>,
    predicates: &mut Vec<WherePredicate>,
) {
    if classify(value_ty) != ValueKind::Parsed || !type_uses_param(value_ty, params) {
        return;
    }
    if seen.insert(value_ty.to_token_stream().to_string()) {
        predicates.push(parse_quote! {
            #value_ty: ::core::str::FromStr + ::std::fmt::Display
        });
    }
}

/// Returns a copy of `generics` with `predicates` appended to its where-clause.
///
/// The result is owned so the caller can hold it while `split_for_impl`
/// borrows from it. When there are no predicates the generics are returned
/// unchanged, so a non-generic derive emits no where-clause.
fn generics_with_bounds(
    generics: &syn::Generics,
    predicates: Vec<WherePredicate>,
) -> syn::Generics {
    let mut generics = generics.clone();
    if !predicates.is_empty() {
        let where_clause = generics.make_where_clause();
        for predicate in predicates {
            where_clause.predicates.push(predicate);
        }
    }
    generics
}

/// Tokens converting `__field` (a `&ironfix_core::field::FieldRef`) into `ty`.
///
/// Every arm propagates a [`DecodeError`](ironfix_core::error::DecodeError)
/// with `?`, so the expansion never panics on a malformed value.
fn decode_expr(ty: &Type) -> TokenStream2 {
    match classify(ty) {
        ValueKind::Text => quote!(::ironfix_core::field::FieldRef::to_string(__field)?),
        ValueKind::Boolean => quote!(::ironfix_core::field::FieldRef::as_bool(__field)?),
        ValueKind::Character => quote!(::ironfix_core::field::FieldRef::as_char(__field)?),
        ValueKind::Bytes => {
            quote!(::std::vec::Vec::from(
                ::ironfix_core::field::FieldRef::as_bytes(__field)
            ))
        }
        ValueKind::Parsed => quote!(::ironfix_core::field::FieldRef::parse::<#ty>(__field)?),
    }
}

/// Tokens appending the wire bytes of `__value` (a `&ty`) to `__buf`.
///
/// The `char` arm rejects a non-ASCII value rather than writing it as
/// multi-byte UTF-8: the FIX `Char` datatype is a single ASCII byte, and the
/// decode side reads exactly one byte through
/// [`FieldRef::as_char`](ironfix_core::field::FieldRef::as_char), so a value
/// like `'é'` could never round-trip. On rejection the field written so far is
/// rolled back to `__field_start`, the marker `write_field` sets around it.
fn write_value(ty: &Type, tag: u32) -> TokenStream2 {
    match classify(ty) {
        ValueKind::Text => quote!(__buf.extend_from_slice(__value.as_bytes());),
        ValueKind::Boolean => quote!(__buf.push(if *__value { b'Y' } else { b'N' });),
        ValueKind::Character => quote! {
            if !__value.is_ascii() {
                __buf.truncate(__field_start);
                return ::core::result::Result::Err(
                    ::ironfix_core::error::EncodeError::InvalidFieldValue {
                        tag: #tag,
                        reason: ::std::string::String::from(
                            "char is not a single ASCII byte",
                        ),
                    },
                );
            }
            __buf.push(*__value as u8);
        },
        ValueKind::Bytes => quote!(__buf.extend_from_slice(__value.as_slice());),
        ValueKind::Parsed => quote! {
            ::std::io::Write::write_fmt(&mut *__buf, ::core::format_args!("{}", __value))
                .map_err(|_| ::ironfix_core::error::EncodeError::InvalidFieldValue {
                    tag: #tag,
                    reason: ::std::string::String::from(
                        "value could not be written to the buffer",
                    ),
                })?;
        },
    }
}

/// Tokens appending the complete `tag=value<SOH>` field to `__buf`.
///
/// A value whose bytes carry SOH would split into two fields on the wire, and a
/// zero-length value would produce the `tag=<SOH>` form that a FIX decoder
/// rejects as "tag specified without a value". Both are rejected with
/// [`EncodeError::InvalidFieldValue`](ironfix_core::error::EncodeError::InvalidFieldValue)
/// and the partially written field is rolled back, leaving `__buf` exactly as
/// it was.
fn write_field(ty: &Type, tag: u32) -> TokenStream2 {
    let prefix_text = format!("{tag}=");
    let prefix = syn::LitByteStr::new(prefix_text.as_bytes(), Span::call_site());
    let value = write_value(ty, tag);
    let soh = SOH;

    quote! {
        {
            let __field_start = __buf.len();
            __buf.extend_from_slice(#prefix);
            let __value_start = __buf.len();
            #value
            if __buf.len() == __value_start {
                __buf.truncate(__field_start);
                return ::core::result::Result::Err(
                    ::ironfix_core::error::EncodeError::InvalidFieldValue {
                        tag: #tag,
                        reason: ::std::string::String::from(
                            "value is empty; a FIX field must carry at least one byte",
                        ),
                    },
                );
            }
            if __buf.iter().skip(__value_start).any(|__byte| *__byte == #soh) {
                __buf.truncate(__field_start);
                return ::core::result::Result::Err(
                    ::ironfix_core::error::EncodeError::InvalidFieldValue {
                        tag: #tag,
                        reason: ::std::string::String::from(
                            "value contains the SOH field delimiter",
                        ),
                    },
                );
            }
            __buf.push(#soh);
        }
    }
}

/// Collects the arguments of every `#[fix(...)]` attribute in `attrs`.
///
/// # Errors
/// Returns the parse error if an attribute is not a comma-separated argument
/// list, so a malformed attribute is a compile error rather than a silently
/// ignored one.
fn fix_metas(attrs: &[Attribute]) -> syn::Result<Vec<Meta>> {
    let mut metas = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("fix") {
            continue;
        }
        let parsed = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
        metas.extend(parsed);
    }
    Ok(metas)
}

/// Rejects any `#[fix(...)]` argument this derive does not understand.
///
/// # Errors
/// Returns an error naming the accepted arguments. Ignoring an unknown
/// argument would let `#[fix(msgtype = "D")]` compile as a struct with no
/// message type at all.
fn reject_unknown_args(metas: &[Meta], allowed: &[&str]) -> syn::Result<()> {
    for meta in metas {
        if !allowed.iter().any(|key| meta.path().is_ident(key)) {
            return Err(syn::Error::new_spanned(
                meta,
                format!(
                    "unknown `fix` argument; this derive accepts: {}",
                    allowed.join(", ")
                ),
            ));
        }
    }
    Ok(())
}

/// Returns the string literal assigned to `key`, if the argument is present.
///
/// # Errors
/// Returns an error if `key` is present but is not written as `key = "literal"`,
/// or if `key` is declared more than once: a duplicate must fail closed rather
/// than silently select one of two protocol identities.
fn string_arg(metas: &[Meta], key: &str) -> syn::Result<Option<LitStr>> {
    let mut found: Option<LitStr> = None;
    for meta in metas {
        if !meta.path().is_ident(key) {
            continue;
        }
        if found.is_some() {
            return Err(syn::Error::new_spanned(
                meta,
                format!("`{key}` is declared more than once; ambiguous metadata is rejected"),
            ));
        }
        let Meta::NameValue(name_value) = meta else {
            return Err(syn::Error::new_spanned(
                meta,
                format!("`{key}` must be written as `{key} = \"...\"`"),
            ));
        };
        let Expr::Lit(ExprLit {
            lit: Lit::Str(literal),
            ..
        }) = &name_value.value
        else {
            return Err(syn::Error::new_spanned(
                &name_value.value,
                format!("`{key}` must be a string literal"),
            ));
        };
        found = Some(literal.clone());
    }
    Ok(found)
}

/// Returns the integer literal assigned to `key`, if the argument is present.
///
/// # Errors
/// Returns an error if `key` is present but is not written as `key = N`, or if
/// `key` is declared more than once: a duplicate tag must fail closed rather
/// than silently select one of two values.
fn int_arg(metas: &[Meta], key: &str) -> syn::Result<Option<LitInt>> {
    let mut found: Option<LitInt> = None;
    for meta in metas {
        if !meta.path().is_ident(key) {
            continue;
        }
        if found.is_some() {
            return Err(syn::Error::new_spanned(
                meta,
                format!("`{key}` is declared more than once; ambiguous metadata is rejected"),
            ));
        }
        let Meta::NameValue(name_value) = meta else {
            return Err(syn::Error::new_spanned(
                meta,
                format!("`{key}` must be written as `{key} = N`"),
            ));
        };
        let Expr::Lit(ExprLit {
            lit: Lit::Int(literal),
            ..
        }) = &name_value.value
        else {
            return Err(syn::Error::new_spanned(
                &name_value.value,
                format!("`{key}` must be an integer literal"),
            ));
        };
        found = Some(literal.clone());
    }
    Ok(found)
}

/// Parses a tag literal, rejecting `0`.
///
/// # Errors
/// Returns an error if the literal does not fit a `u32` or is `0`, which
/// `ironfix_core::field::FieldTag::try_new` also rejects: FIX tags start at 1.
fn parse_tag(literal: &LitInt) -> syn::Result<u32> {
    let tag: u32 = literal.base10_parse()?;
    if tag == 0 {
        return Err(syn::Error::new_spanned(
            literal,
            "0 is not a legal FIX tag: tags are positive integers starting at 1",
        ));
    }
    Ok(tag)
}

/// Checks that `literal` can appear verbatim in tag 35.
///
/// # Errors
/// Returns an error if the value is empty, longer than [`MSG_TYPE_MAX_LEN`]
/// bytes, or carries a byte that is not printable ASCII or is `=`. The rules
/// mirror `ironfix_core::message::MsgType::new`, so a derived `MSG_TYPE` is
/// always a value that can round-trip through tag 35.
fn validate_msg_type(literal: &LitStr) -> syn::Result<()> {
    let value = literal.value();
    if value.is_empty() {
        return Err(syn::Error::new_spanned(
            literal,
            "`msg_type` must not be empty: tag 35 always carries at least one byte",
        ));
    }
    if value.len() > MSG_TYPE_MAX_LEN {
        return Err(syn::Error::new_spanned(
            literal,
            format!(
                "`msg_type` is {} bytes, exceeding the {MSG_TYPE_MAX_LEN}-byte bound a decoded \
                 MsgType can hold; it could never match a message off the wire",
                value.len()
            ),
        ));
    }
    for (position, byte) in value.bytes().enumerate() {
        if !byte.is_ascii_graphic() || byte == b'=' {
            return Err(syn::Error::new_spanned(
                literal,
                format!(
                    "`msg_type` contains illegal byte {byte:#04x} at offset {position}: only \
                     printable ASCII except '=' can appear in tag 35"
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses derive input written as source, failing the test on a bad
    /// fixture rather than on the code under test.
    #[track_caller]
    fn parse_input(source: &str) -> DeriveInput {
        match syn::parse_str::<DeriveInput>(source) {
            Ok(input) => input,
            Err(err) => panic!("test fixture must parse as derive input: {err}"),
        }
    }

    /// Expands a successful derive and returns its tokens with all whitespace
    /// removed, so path assertions do not depend on token spacing.
    ///
    /// Also asserts the expansion is syntactically valid Rust by reparsing it
    /// as an `impl` block.
    #[track_caller]
    fn expand_ok(expand: fn(&DeriveInput) -> syn::Result<TokenStream2>, source: &str) -> String {
        match expand(&parse_input(source)) {
            Ok(tokens) => match syn::parse2::<syn::ItemImpl>(tokens.clone()) {
                Ok(_) => tokens.to_string().replace([' ', '\n'], ""),
                Err(err) => panic!("expansion must be a valid impl block: {err}\n{tokens}"),
            },
            Err(err) => panic!("expansion must succeed: {err}"),
        }
    }

    /// Expands a derive that must fail and returns the compile error message.
    #[track_caller]
    fn expand_err(expand: fn(&DeriveInput) -> syn::Result<TokenStream2>, source: &str) -> String {
        match expand(&parse_input(source)) {
            Ok(tokens) => panic!("expansion must fail, produced: {tokens}"),
            Err(err) => err.to_string(),
        }
    }

    /// A well-formed message fixture covering required, optional, and
    /// specially-typed fields.
    const MESSAGE: &str = r#"
        #[fix(msg_type = "D")]
        struct NewOrderSingle {
            #[fix(tag = 11)]
            cl_ord_id: String,
            #[fix(tag = 54)]
            side: char,
            #[fix(tag = 44)]
            price: Option<Decimal>,
            #[fix(tag = 43)]
            poss_dup_flag: bool,
            #[fix(tag = 96)]
            raw_data: Vec<u8>,
        }
    "#;

    #[test]
    fn test_fix_message_valid_struct_expands_to_an_impl_block() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains("impl::ironfix_core::message::FixMessageforNewOrderSingle"));
    }

    #[test]
    fn test_fix_message_expansion_contains_no_todo() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(!tokens.contains("todo!"));
        assert!(!tokens.contains("unimplemented!"));
        assert!(!tokens.contains("panic!"));
        assert!(!tokens.contains(".unwrap("));
        assert!(!tokens.contains(".expect("));
    }

    #[test]
    fn test_fix_message_expansion_declares_the_declared_msg_type() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains(r#"constMSG_TYPE:&'staticstr="D""#));
    }

    #[test]
    fn test_fix_message_expansion_uses_absolute_paths_only() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains("::ironfix_core::message::RawMessage::get_field"));
        assert!(tokens.contains("::ironfix_core::error::DecodeError::MissingRequiredField"));
        assert!(tokens.contains("::core::result::Result::Ok"));
        // A bare `RawMessage` / `DecodeError` would only compile where the
        // user happens to have imported it.
        assert!(!tokens.contains("(raw:&RawMessage"));
    }

    #[test]
    fn test_fix_message_checks_msg_type_before_decoding() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains("::ironfix_core::message::MsgType::as_str"));
        assert!(tokens.contains("tag:35u32"));
    }

    #[test]
    fn test_fix_message_required_field_is_a_typed_error_when_absent() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains("MissingRequiredField{tag:11u32,}"));
    }

    #[test]
    fn test_fix_message_optional_field_decodes_to_none_when_absent() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains("::core::option::Option::None=>::core::option::Option::None"));
    }

    #[test]
    fn test_fix_message_bool_field_uses_the_fix_y_n_codes() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains("::ironfix_core::field::FieldRef::as_bool"));
        assert!(tokens.contains("b'Y'"));
        assert!(tokens.contains("b'N'"));
    }

    #[test]
    fn test_fix_message_char_field_uses_the_single_byte_accessor() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains("::ironfix_core::field::FieldRef::as_char"));
    }

    #[test]
    fn test_fix_message_unknown_type_falls_back_to_from_str() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains("::ironfix_core::field::FieldRef::parse::<Decimal>"));
    }

    #[test]
    fn test_fix_message_byte_field_copies_raw_bytes() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains("::ironfix_core::field::FieldRef::as_bytes"));
    }

    #[test]
    fn test_fix_message_encode_emits_tag_prefix_and_soh() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains(r#"extend_from_slice(b"11=")"#));
        assert!(tokens.contains("__buf.push(1u8)"));
    }

    #[test]
    fn test_fix_message_encode_rejects_a_value_carrying_soh() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        assert!(tokens.contains("::ironfix_core::error::EncodeError::InvalidFieldValue"));
        assert!(tokens.contains("__buf.truncate(__field_start)"));
    }

    #[test]
    fn test_fix_message_char_encode_rejects_a_non_ascii_char() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        // The FIX `Char` datatype is a single ASCII byte, and decode reads
        // exactly one byte via `as_char`; a non-ASCII char is rejected rather
        // than written as multi-byte UTF-8 that could never round-trip.
        assert!(tokens.contains("__value.is_ascii()"));
        assert!(tokens.contains("::ironfix_core::error::EncodeError::InvalidFieldValue"));
        assert!(!tokens.contains("encode_utf8"));
    }

    #[test]
    fn test_fix_message_char_encode_writes_one_ascii_byte_to_match_decode() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        // An ASCII char encodes to the single byte that `as_char` reads back,
        // so it round-trips.
        assert!(tokens.contains("__buf.push(*__valueasu8)"));
        assert!(tokens.contains("::ironfix_core::field::FieldRef::as_char"));
    }

    #[test]
    fn test_fix_message_encode_rejects_an_empty_value() {
        let tokens = expand_ok(expand_fix_message, MESSAGE);
        // A zero-length value would emit the `tag=<SOH>` "tag specified without
        // a value" form a FIX decoder rejects; encode errors and rolls the
        // field back instead.
        assert!(tokens.contains("__buf.len()==__value_start"));
        assert!(tokens.contains("__buf.truncate(__field_start)"));
        assert!(tokens.contains("::ironfix_core::error::EncodeError::InvalidFieldValue"));
    }

    #[test]
    fn test_fix_message_missing_msg_type_is_a_compile_error() {
        let err = expand_err(
            expand_fix_message,
            "struct Order { #[fix(tag = 11)] cl_ord_id: String }",
        );
        assert!(err.contains("msg_type"));
        assert!(err.contains("never defaulted"));
    }

    #[test]
    fn test_fix_message_empty_msg_type_is_a_compile_error() {
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msg_type = "")] struct Order {}"#,
        );
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn test_fix_message_msg_type_carrying_a_separator_is_a_compile_error() {
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msg_type = "A=B")] struct Order {}"#,
        );
        assert!(err.contains("illegal byte"));
    }

    #[test]
    fn test_fix_message_over_long_msg_type_is_a_compile_error() {
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msg_type = "U99999999")] struct Order {}"#,
        );
        assert!(err.contains("9 bytes"));
    }

    #[test]
    fn test_fix_message_non_string_msg_type_is_a_compile_error() {
        let err = expand_err(expand_fix_message, "#[fix(msg_type = 0)] struct Order {}");
        assert!(err.contains("string literal"));
    }

    #[test]
    fn test_fix_message_unknown_argument_is_a_compile_error() {
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msgtype = "D")] struct Order {}"#,
        );
        assert!(err.contains("unknown `fix` argument"));
    }

    #[test]
    fn test_fix_message_field_without_a_tag_is_a_compile_error() {
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] struct Order { cl_ord_id: String }"#,
        );
        assert!(err.contains("cl_ord_id"));
        assert!(err.contains("never defaulted to 0"));
    }

    #[test]
    fn test_fix_message_tag_zero_is_a_compile_error() {
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] struct Order { #[fix(tag = 0)] cl_ord_id: String }"#,
        );
        assert!(err.contains("0 is not a legal FIX tag"));
    }

    #[test]
    fn test_fix_message_duplicate_tag_is_a_compile_error() {
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] struct Order {
                #[fix(tag = 11)] a: String,
                #[fix(tag = 11)] b: String,
            }"#,
        );
        assert!(err.contains("already declared by field `a`"));
    }

    #[test]
    fn test_fix_message_on_an_enum_is_a_compile_error() {
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] enum Order { A }"#,
        );
        assert!(err.contains("named fields only"));
    }

    #[test]
    fn test_fix_message_on_a_tuple_struct_is_a_compile_error() {
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] struct Order(String);"#,
        );
        assert!(err.contains("named fields only"));
    }

    #[test]
    fn test_fix_message_generic_struct_carries_its_bounds() {
        let tokens = expand_ok(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] struct Order<T: Clone> { #[fix(tag = 11)] id: T }"#,
        );
        assert!(tokens.contains("impl<T:Clone>::ironfix_core::message::FixMessageforOrder<T>"));
    }

    #[test]
    fn test_fix_message_generic_fallback_field_gains_fromstr_and_display_bounds() {
        // A field of a bare type parameter takes the fallback path, which calls
        // `FieldRef::parse::<T>` (needs `FromStr`) and formats with `{}` (needs
        // `Display`); the derive must add those or the impl will not type-check.
        let tokens = expand_ok(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] struct Order<T: Clone> { #[fix(tag = 11)] id: T }"#,
        );
        assert!(tokens.contains("whereT:::core::str::FromStr+::std::fmt::Display"));
    }

    #[test]
    fn test_fix_message_optional_generic_field_bounds_the_inner_type() {
        // `Option<T>` encodes and decodes its inner `T`, so the bound is on `T`,
        // not on `Option<T>`.
        let tokens = expand_ok(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] struct Order<T> { #[fix(tag = 44)] price: Option<T> }"#,
        );
        assert!(tokens.contains("whereT:::core::str::FromStr+::std::fmt::Display"));
    }

    #[test]
    fn test_fix_message_concrete_fallback_field_adds_no_where_clause() {
        // A concrete fallback type already satisfies the bounds, so no
        // redundant where-clause is emitted.
        let tokens = expand_ok(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] struct Order { #[fix(tag = 44)] price: Decimal }"#,
        );
        assert!(!tokens.contains("::core::str::FromStr"));
        assert!(!tokens.contains("::std::fmt::Display"));
    }

    #[test]
    fn test_fix_message_string_generic_field_needs_no_bounds() {
        // A `String`-typed field takes the text path, not the fallback, so a
        // generic struct with only such a field gains no bounds.
        let tokens = expand_ok(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] struct Order<T> { #[fix(tag = 11)] id: String, #[fix(tag = 55)] other: T }"#,
        );
        // `other: T` still takes the fallback and is bounded; `id: String` is
        // not what drove it.
        assert!(tokens.contains("whereT:::core::str::FromStr+::std::fmt::Display"));
    }

    #[test]
    fn test_fix_message_duplicate_msg_type_key_is_a_compile_error() {
        // Two `msg_type` values would silently pick one protocol identity.
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msg_type = "D", msg_type = "E")] struct Order {}"#,
        );
        assert!(err.contains("declared more than once"));
    }

    #[test]
    fn test_fix_message_duplicate_field_tag_key_is_a_compile_error() {
        // Two `tag` values on one field would silently pick one tag.
        let err = expand_err(
            expand_fix_message,
            r#"#[fix(msg_type = "D")] struct Order { #[fix(tag = 11, tag = 12)] id: String }"#,
        );
        assert!(err.contains("declared more than once"));
    }

    #[test]
    fn test_fix_field_newtype_expands_to_an_impl_block() {
        let tokens = expand_ok(expand_fix_field, "#[fix(tag = 11)] struct ClOrdId(String);");
        assert!(tokens.contains("impl::ironfix_core::field::FixFieldforClOrdId"));
        assert!(tokens.contains("constTAG:u32=11u32"));
        assert!(tokens.contains("Self(__inner)"));
        assert!(!tokens.contains("todo!"));
    }

    #[test]
    fn test_fix_field_named_single_field_struct_expands() {
        let tokens = expand_ok(
            expand_fix_field,
            "#[fix(tag = 54)] struct Side { code: char }",
        );
        assert!(tokens.contains("Self{code:__inner}"));
        assert!(tokens.contains("::ironfix_core::field::FieldRef::as_char"));
    }

    #[test]
    fn test_fix_field_encode_writes_the_whole_field() {
        let tokens = expand_ok(expand_fix_field, "#[fix(tag = 11)] struct ClOrdId(String);");
        assert!(tokens.contains(r#"extend_from_slice(b"11=")"#));
        assert!(tokens.contains("__buf.push(1u8)"));
    }

    #[test]
    fn test_fix_field_missing_tag_is_a_compile_error() {
        let err = expand_err(expand_fix_field, "struct ClOrdId(String);");
        assert!(err.contains("never defaulted to 0"));
    }

    #[test]
    fn test_fix_field_tag_zero_is_a_compile_error() {
        let err = expand_err(expand_fix_field, "#[fix(tag = 0)] struct ClOrdId(String);");
        assert!(err.contains("0 is not a legal FIX tag"));
    }

    #[test]
    fn test_fix_field_non_integer_tag_is_a_compile_error() {
        let err = expand_err(
            expand_fix_field,
            r#"#[fix(tag = "11")] struct ClOrdId(String);"#,
        );
        assert!(err.contains("integer literal"));
    }

    #[test]
    fn test_fix_field_multiple_fields_is_a_compile_error() {
        let err = expand_err(
            expand_fix_field,
            "#[fix(tag = 11)] struct ClOrdId(String, u32);",
        );
        assert!(err.contains("exactly one field"));
    }

    #[test]
    fn test_fix_field_option_inner_is_a_compile_error() {
        let err = expand_err(
            expand_fix_field,
            "#[fix(tag = 11)] struct ClOrdId(Option<String>);",
        );
        assert!(err.contains("must not be an `Option`"));
    }

    #[test]
    fn test_fix_field_on_an_enum_is_a_compile_error() {
        let err = expand_err(expand_fix_field, "#[fix(tag = 11)] enum ClOrdId { A }");
        assert!(err.contains("exactly one value"));
    }

    #[test]
    fn test_fix_field_generic_inner_gains_fromstr_and_display_bounds() {
        // A generic wrapped value takes the fallback path in both `decode` and
        // `encode`, so its bound must be added for the impl to type-check.
        let tokens = expand_ok(
            expand_fix_field,
            "#[fix(tag = 11)] struct Wrapper<T: Clone>(T);",
        );
        assert!(tokens.contains("whereT:::core::str::FromStr+::std::fmt::Display"));
    }

    #[test]
    fn test_fix_field_duplicate_tag_key_is_a_compile_error() {
        // Two `tag` values would silently pick one tag.
        let err = expand_err(
            expand_fix_field,
            "#[fix(tag = 11, tag = 12)] struct ClOrdId(String);",
        );
        assert!(err.contains("declared more than once"));
    }

    #[test]
    fn test_classify_matches_types_by_written_name() {
        let text = parse_input("struct S { f: String }");
        let alias = parse_input("struct S { f: Symbol }");
        let bytes = parse_input("struct S { f: Vec<u8> }");
        let other = parse_input("struct S { f: Vec<Leg> }");

        assert_eq!(classify(&first_field_type(&text)), ValueKind::Text);
        // An alias cannot be resolved by a macro, so it takes the fallback.
        assert_eq!(classify(&first_field_type(&alias)), ValueKind::Parsed);
        assert_eq!(classify(&first_field_type(&bytes)), ValueKind::Bytes);
        assert_eq!(classify(&first_field_type(&other)), ValueKind::Parsed);
    }

    /// Returns the type of the first field of a single-field fixture struct.
    #[track_caller]
    fn first_field_type(input: &DeriveInput) -> Type {
        let Data::Struct(data) = &input.data else {
            panic!("fixture must be a struct");
        };
        match data.fields.iter().next() {
            Some(field) => field.ty.clone(),
            None => panic!("fixture must have one field"),
        }
    }

    #[test]
    fn test_option_inner_unwraps_only_option() {
        let optional = parse_input("struct S { f: Option<String> }");
        let plain = parse_input("struct S { f: String }");
        assert!(option_inner(&first_field_type(&optional)).is_some());
        assert!(option_inner(&first_field_type(&plain)).is_none());
    }
}
