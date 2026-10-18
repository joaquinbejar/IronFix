/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 18/10/26
******************************************************************************/

//! The FIXP value types: session identifier, flow types, nanosecond time,
//! credentials, and the reject and termination codes.
//!
//! Every enumeration here is the `enum` of the same name in the FIXP SBE
//! schema (`spec/SBEschemaForFIXP.xml`, schema id 2748, version 0), with the
//! same numeric values. Decoding an undefined value is a typed error
//! ([`crate::FixpDecodeError::InvalidEnumValue`]), never a default.

use crate::error::FixpEncodeError;
use std::fmt;

/// Largest length of an SBE variable-length field in this schema, in bytes:
/// both `Object` and `CharacterString` carry a `uint16` length prefix.
pub const MAX_VAR_DATA_LEN: usize = u16::MAX as usize;

/// A FIXP session identifier: a 16-byte UUID (FIXP v1.1 section 3.4.1).
///
/// The client assigns it; the session core never generates one, because it
/// reads no source of entropy (ADR-0002). FIXP asks for an RFC 4122 version 4
/// UUID. This type carries any 16 bytes so that a counterparty using another
/// UUID version is not refused for it; the all-zero (nil) UUID is the one
/// value the server rejects (Appendix A 7.1.7.3).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// The nil UUID, all bits zero. Never a valid session identifier.
    pub const NIL: Self = Self([0; 16]);

    /// Wraps the 16 bytes of a UUID, in RFC 4122 byte order.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the 16 bytes of the UUID.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns `true` for the nil UUID.
    #[must_use]
    pub const fn is_nil(&self) -> bool {
        u128::from_be_bytes(self.0) == 0
    }
}

impl fmt::Display for SessionId {
    /// Formats the canonical UUID text form, `8-4-4-4-12` lowercase hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({self})")
    }
}

/// The delivery guarantee of one direction of a session (FIXP v1.1
/// section 3.4.4). Schema enum `FlowType`, encoded as `uint8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FlowType {
    /// Exactly-once delivery: gaps are recovered by retransmission.
    Recoverable = 0,
    /// At-most-once delivery: gaps are reported with NotApplied and recovery
    /// is up to the application.
    Idempotent = 1,
    /// Best effort: no sequence numbers at the session layer.
    Unsequenced = 2,
    /// No application messages in this direction.
    None = 3,
}

impl FlowType {
    /// Returns the wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parses a wire value, `None` if the schema does not define it.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Recoverable),
            1 => Some(Self::Idempotent),
            2 => Some(Self::Unsequenced),
            3 => Some(Self::None),
            _ => None,
        }
    }

    /// Returns `true` for the flows that number application messages:
    /// Recoverable and Idempotent (FIXP v1.1 section 3.5.1).
    #[must_use]
    pub const fn is_sequenced(self) -> bool {
        match self {
            Self::Recoverable | Self::Idempotent => true,
            Self::Unsequenced | Self::None => false,
        }
    }
}

/// Nanoseconds since the Unix epoch, the FIXP `nanotime` type (FIXP v1.1
/// section 3.2): the full `u64` range, as on the wire.
///
/// FIXP uses it as the identifier of a request (`Timestamp`) that the response
/// echoes (`RequestTimestamp`), so it is compared, never interpreted, by the
/// session core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nanotime(u64);

impl Nanotime {
    /// Wraps a nanosecond count since the Unix epoch.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Returns the nanosecond count since the Unix epoch.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

impl From<ironfix_core::Timestamp> for Nanotime {
    fn from(timestamp: ironfix_core::Timestamp) -> Self {
        Self(timestamp.as_nanos())
    }
}

/// Opaque credentials carried by Negotiate, NegotiationResponse and Establish
/// (FIXP v1.1 section 3.4.2, datatype `Object`).
///
/// FIXP does not define their format; counterparties agree on it. They are a
/// secret, so this type never shows them: its `Debug` prints only the length,
/// it implements no `Display`, and the session core never logs them. Read
/// them with [`Credentials::expose`] where they are checked.
///
/// Equality compares the bytes in time that depends on their contents; use a
/// constant-time comparison where the check guards authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials(Vec<u8>);

impl Credentials {
    /// Wraps credential bytes.
    ///
    /// # Errors
    /// Returns [`FixpEncodeError::VarDataTooLong`] above
    /// [`MAX_VAR_DATA_LEN`] bytes, the most the field's `uint16` length
    /// prefix can carry.
    pub fn try_new(bytes: impl Into<Vec<u8>>) -> Result<Self, FixpEncodeError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_VAR_DATA_LEN {
            return Err(FixpEncodeError::VarDataTooLong {
                field: "Credentials",
                len: bytes.len(),
                max: MAX_VAR_DATA_LEN,
            });
        }
        Ok(Self(bytes))
    }

    /// Wraps bytes already known to fit the length prefix (decoded input).
    pub(crate) const fn from_wire(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the credential bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length of the credentials in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the credentials are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credentials(<redacted, {} bytes>)", self.0.len())
    }
}

/// Defines a `uint8` schema enumeration with `as_u8` / `from_u8`.
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident = $value:literal, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum $name {
            $( $(#[$vmeta])* $variant = $value, )+
        }

        impl $name {
            /// Returns the wire value.
            #[must_use]
            pub const fn as_u8(self) -> u8 {
                self as u8
            }

            /// Parses a wire value, `None` if the schema does not define it.
            #[must_use]
            pub const fn from_u8(value: u8) -> Option<Self> {
                match value {
                    $( $value => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

wire_enum! {
    /// Why a server refused a Negotiate (FIXP v1.1 section 4.2.3). Schema
    /// enum `NegotiationRejectCode`.
    NegotiationRejectCode {
        /// Identity not recognised, or not authorised for the service.
        Credentials = 0,
        /// The server does not support the requested client flow type.
        FlowTypeNotSupported = 1,
        /// The session ID is not unique.
        DuplicateId = 2,
        /// Any other reason the server cannot create the session.
        Unspecified = 3,
    }
}

wire_enum! {
    /// Why a server refused an Establish (FIXP v1.1 section 4.3.3). Schema
    /// enum `EstablishmentRejectCode`.
    EstablishmentRejectCode {
        /// Establish was not preceded by a negotiation, or the session was
        /// finalized and must be renegotiated.
        Unnegotiated = 0,
        /// EstablishmentAck was already sent; the Establish was redundant.
        AlreadyEstablished = 1,
        /// The user is not authorised.
        SessionBlocked = 2,
        /// The KeepaliveInterval is out of the accepted range.
        KeepaliveInterval = 3,
        /// Identity not recognised, or not authorised for the service.
        Credentials = 4,
        /// Any other reason the server cannot establish the session.
        Unspecified = 5,
    }
}

wire_enum! {
    /// Why a RetransmitRequest was refused (FIXP v1.1 section 4.6.2.3).
    /// Schema enum `RetransmitRejectCode`.
    RetransmitRejectCode {
        /// FromSeqNo + Count is beyond the range of sequence numbers.
        OutOfRange = 0,
        /// The SessionId is unknown or not authorised for the requester.
        InvalidSession = 1,
        /// Count exceeds the local limit on a retransmission.
        RequestLimitExceeded = 2,
    }
}

wire_enum! {
    /// Why a transport is being unbound (FIXP v1.1 section 4.4). Schema enum
    /// `TerminationCode`.
    TerminationCode {
        /// Normal unbinding.
        Finished = 0,
        /// An error, such as a protocol violation or a lapsed keepalive.
        UnspecifiedError = 1,
        /// A RetransmitRequest for messages out of bounds (section 4.6.5).
        ReRequestOutOfBounds = 2,
        /// A RetransmitRequest while another was being answered
        /// (section 4.6.4).
        ReRequestInProgress = 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_display_is_canonical_uuid_text() {
        let id = SessionId::from_bytes([
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x42, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17,
            0x40, 0x00,
        ]);
        assert_eq!(id.to_string(), "123e4567-e89b-42d3-a456-426614174000");
        assert_eq!(
            format!("{id:?}"),
            "SessionId(123e4567-e89b-42d3-a456-426614174000)"
        );
        assert!(!id.is_nil());
        assert!(SessionId::NIL.is_nil());
        assert_eq!(id.as_bytes()[0], 0x12);
    }

    #[test]
    fn test_flow_type_wire_values_round_trip() {
        for flow in [
            FlowType::Recoverable,
            FlowType::Idempotent,
            FlowType::Unsequenced,
            FlowType::None,
        ] {
            assert_eq!(FlowType::from_u8(flow.as_u8()), Some(flow));
        }
        assert_eq!(FlowType::from_u8(4), None);
        assert!(FlowType::Recoverable.is_sequenced());
        assert!(FlowType::Idempotent.is_sequenced());
        assert!(!FlowType::Unsequenced.is_sequenced());
        assert!(!FlowType::None.is_sequenced());
    }

    #[test]
    fn test_reject_and_termination_codes_round_trip_and_refuse_unknown_values() {
        for value in 0..=3 {
            let code = NegotiationRejectCode::from_u8(value);
            assert_eq!(code.map(NegotiationRejectCode::as_u8), Some(value));
        }
        assert_eq!(NegotiationRejectCode::from_u8(4), None);
        for value in 0..=5 {
            let code = EstablishmentRejectCode::from_u8(value);
            assert_eq!(code.map(EstablishmentRejectCode::as_u8), Some(value));
        }
        assert_eq!(EstablishmentRejectCode::from_u8(6), None);
        for value in 0..=2 {
            let code = RetransmitRejectCode::from_u8(value);
            assert_eq!(code.map(RetransmitRejectCode::as_u8), Some(value));
        }
        assert_eq!(RetransmitRejectCode::from_u8(3), None);
        for value in 0..=3 {
            let code = TerminationCode::from_u8(value);
            assert_eq!(code.map(TerminationCode::as_u8), Some(value));
        }
        assert_eq!(TerminationCode::from_u8(255), None);
    }

    #[test]
    fn test_credentials_debug_never_shows_the_secret() {
        let credentials = Credentials::try_new(b"hunter2".to_vec());
        assert!(credentials.is_ok());
        if let Ok(credentials) = credentials {
            let debug = format!("{credentials:?}");
            assert_eq!(debug, "Credentials(<redacted, 7 bytes>)");
            assert!(!debug.contains("hunter2"));
            assert_eq!(credentials.expose(), b"hunter2");
            assert_eq!(credentials.len(), 7);
            assert!(!credentials.is_empty());
        }
    }

    #[test]
    fn test_credentials_try_new_refuses_more_than_the_length_prefix_carries() {
        let too_long = Credentials::try_new(vec![0_u8; MAX_VAR_DATA_LEN + 1]);
        assert_eq!(
            too_long,
            Err(FixpEncodeError::VarDataTooLong {
                field: "Credentials",
                len: MAX_VAR_DATA_LEN + 1,
                max: MAX_VAR_DATA_LEN,
            })
        );
        assert!(Credentials::try_new(vec![0_u8; MAX_VAR_DATA_LEN]).is_ok());
    }

    #[test]
    fn test_nanotime_from_core_timestamp_keeps_the_count() {
        let timestamp = ironfix_core::Timestamp::from_nanos(1_700_000_000_123_456_789);
        assert!(timestamp.is_ok());
        if let Ok(timestamp) = timestamp {
            let nanotime = Nanotime::from(timestamp);
            assert_eq!(nanotime.as_nanos(), 1_700_000_000_123_456_789);
            assert_eq!(Nanotime::from_nanos(5).as_nanos(), 5);
        }
    }
}
