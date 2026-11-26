//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48). The TPDU size a Location proposes unless told otherwise is
//! declared here, and the code takes it from here.

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// The TPDU size code proposed by default: 2^10, 1024 bytes.
pub const DEFAULT_SIZE_CODE: u8 = 10;

/// Every setting a Location takes beyond its address, where a Receive
/// Location listens — `0.0.0.0:102` the standard port; a Send Location
/// calls the target its route gives.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "src_tsap",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "This side's TSAP a call is made from, in hex; the usual client \
                      TSAP when left out.",
            applies: Applies::Send,
        },
        Setting {
            name: "dst_tsap",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "The far end's TSAP a call is made to, in hex; the usual server \
                      TSAP when left out.",
            applies: Applies::Send,
        },
        Setting {
            name: "tpdu_size_code",
            kind: Kind::Integer {
                minimum: 7,
                maximum: 13,
            },
            presence: Presence::Default(Fixed::Integer(DEFAULT_SIZE_CODE as i64)),
            meaning: "The TPDU size proposed or accepted at most, as the power of two \
                      of its bytes.",
            applies: Applies::Both,
        },
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a peer that stops mid-message is waited on; unbounded \
             when left out.",
        ),
    ],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["cotp"];
