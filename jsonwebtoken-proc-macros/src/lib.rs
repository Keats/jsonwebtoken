//! This library provides convenient derive and attribute macros for custom Header and Claim
//! structs for `jsonwebtoken`.
//!
//! Example
//! ```rust
//! use jsonwebtoken::Algorithm;
//! use jsonwebtoken::macros::header;
//! #[header]
//! struct CustomJwtHeader {
//!     // `alg` is the only required struct field
//!     alg: Algorithm,
//!     custom_header: Option<String>,
//!     another_custom_header: String,
//! }
//! ````
extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, Item, ItemStruct, parse_macro_input};

/// Convenience macro for JWT header structs
///
/// Adds the following derive macros:
/// ```rust
/// #[derive(
///     Debug,
///     Clone,
///     Default,
///     serde::Serialize,
///     serde::Deserialize
/// )]
/// ```
#[proc_macro_attribute]
pub fn claims(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item = parse_macro_input!(input as Item);

    match &mut item {
        Item::Struct(ItemStruct { attrs, .. }) => {
            attrs.push(
                syn::parse_quote!(#[derive(Debug, Clone, Default, jsonwebtoken::serde::Serialize, jsonwebtoken::serde::Deserialize)]),
            );
            quote!(#item).into()
        }
        _ => syn::Error::new_spanned(&item, "#[header] can only be used on structs")
            .to_compile_error()
            .into(),
    }
}

/// Convenience macro for JWT header structs
///
/// Adds the following derive macros:
/// ```rust
/// #[derive(
///     Debug,
///     Clone,
///     Default,
///     jsonwebtoken::macros::Header,
///     serde::Serialize,
///     serde::Deserialize
/// )]
/// ```
#[proc_macro_attribute]
pub fn header(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut item = parse_macro_input!(input as Item);

    match &mut item {
        Item::Struct(ItemStruct { attrs, .. }) => {
            attrs.push(syn::parse_quote!(#[derive(Debug, Clone, Default, jsonwebtoken::serde::Serialize, jsonwebtoken::serde::Deserialize, jsonwebtoken::macros::Header)]));
            quote!(#item).into()
        }
        _ => syn::Error::new_spanned(&item, "#[header] can only be used on structs")
            .to_compile_error()
            .into(),
    }
}

/// Derive macro required for custom JWT headers used with `jsonwebtoken`
///
/// Requires an `alg: jsonwebtoken::Algorithm` field exists in the struct
#[proc_macro_derive(Header)]
pub fn derive_header(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics ::jsonwebtoken::header::FromEncoded for #name #ty_generics #where_clause {}
        impl #impl_generics ::jsonwebtoken::header::Alg for #name #ty_generics #where_clause {
            fn alg(&self) -> &::jsonwebtoken::Algorithm {
                &self.alg
            }
        }
    };

    TokenStream::from(expanded)
}
