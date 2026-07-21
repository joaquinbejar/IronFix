/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Zero-copy FIX message decoder.
//!
//! This module provides a high-performance decoder that parses FIX messages
//! without allocating memory for field values. Field values are returned as
//! references to the original buffer.
//!
//! The decoder is an untrusted-input parser: every length and offset is
//! attacker-controlled, so all arithmetic is checked, every slice is taken
//! with [`slice::get`], and every malformed frame maps to a typed
//! [`DecodeError`] instead of a panic or a silent default.

use crate::checksum::{calculate_checksum, parse_checksum};
use ironfix_core::error::DecodeError;
use ironfix_core::field::FieldRef;
use ironfix_core::message::{MsgType, RawMessage};
use memchr::memchr;
use smallvec::SmallVec;
use std::ops::Range;

/// SOH (Start of Header) delimiter, and the `=` tag/value separator.
///
/// Both are defined once at the crate root and re-exported here, so
/// `ironfix_tagvalue::decoder::SOH` keeps resolving to the same item as
/// `ironfix_tagvalue::SOH`.
pub use crate::{EQUALS, SOH};

/// Maximum number of digits accepted in a tag number.
const MAX_TAG_DIGITS: usize = 10;

/// Maximum number of digits accepted in a `LENGTH` field value.
const MAX_LENGTH_DIGITS: usize = 10;

/// Maximum number of input bytes echoed back in an error message.
///
/// The offending bytes are attacker-controlled, so the diagnostic string is
/// bounded rather than sized from the input.
const MAX_TAG_DIAGNOSTIC_LEN: usize = 16;

/// Lowest tag number that is a `LENGTH` field framing a paired `DATA` field.
///
/// The guard at the top of [`paired_data_tag`]; kept next to the table it
/// bounds so the two are read together.
const FIRST_LENGTH_TAG: u32 = 90;

/// Lowest tag number that is a `DATA` field, i.e. the guard at the top of
/// [`is_data_tag`].
const FIRST_DATA_TAG: u32 = 89;

/// Reference table of the spec-defined `(length_tag, data_tag)` pairs.
///
/// Test-only, and the single source of truth both test modules cross-check
/// against: [`paired_data_tag`] and [`is_data_tag`] are hand-written `match`
/// arms, and the encoder's round-trip test walks this table so every pair the
/// decoder frames by count is proven emittable.
///
/// See [`paired_data_tag`] for how the pairs were derived and which versions
/// they span.
#[cfg(test)]
pub(crate) const LENGTH_DATA_PAIRS: [(u32, u32); 83] = [
    // FIX 4.0
    (90, 91), // SecureDataLen / SecureData
    (93, 89), // SignatureLength / Signature
    (95, 96), // RawDataLength / RawData
    // FIX 4.2
    (212, 213), // XmlDataLen / XmlData
    (348, 349), // EncodedIssuerLen / EncodedIssuer
    (350, 351), // EncodedSecurityDescLen / EncodedSecurityDesc
    (352, 353), // EncodedListExecInstLen / EncodedListExecInst
    (354, 355), // EncodedTextLen / EncodedText
    (356, 357), // EncodedSubjectLen / EncodedSubject
    (358, 359), // EncodedHeadlineLen / EncodedHeadline
    (360, 361), // EncodedAllocTextLen / EncodedAllocText
    (362, 363), // EncodedUnderlyingIssuerLen / EncodedUnderlyingIssuer
    (364, 365), // EncodedUnderlyingSecurityDescLen / EncodedUnderlyingSecurityDesc
    (445, 446), // EncodedListStatusTextLen / EncodedListStatusText
    // FIX 4.3
    (618, 619), // EncodedLegIssuerLen / EncodedLegIssuer
    (621, 622), // EncodedLegSecurityDescLen / EncodedLegSecurityDesc
    // FIX 5.0 SP1
    (1184, 1185), // SecurityXMLLen / SecurityXML
    (1277, 1278), // DerivativeEncodedIssuerLen / DerivativeEncodedIssuer
    (1280, 1281), // DerivativeEncodedSecurityDescLen / DerivativeEncodedSecurityDesc
    (1282, 1283), // DerivativeSecurityXMLLen / DerivativeSecurityXML
    (1397, 1398), // EncodedMktSegmDescLen / EncodedMktSegmDesc
    (1401, 1402), // EncryptedPasswordLen / EncryptedPassword
    (1403, 1404), // EncryptedNewPasswordLen / EncryptedNewPassword
    // FIX 5.0 SP2
    (1468, 1469),   // EncodedSecurityListDescLen / EncodedSecurityListDesc
    (1525, 1527),   // EncodedDocumentationTextLen / EncodedDocumentationText
    (1578, 1579),   // EncodedEventTextLen / EncodedEventText
    (1620, 1621),   // InstrumentScopeEncodedSecurityDescLen / InstrumentScopeEncodedSecurityDesc
    (1664, 1665),   // EncodedRejectTextLen / EncodedRejectText
    (1678, 1697),   // EncodedOptionExpirationDescLen / EncodedOptionExpirationDesc
    (1733, 1734),   // EncodedFirmAllocTextLen / EncodedFirmAllocText
    (1871, 1872),   // LegSecurityXMLLen / LegSecurityXML
    (1874, 1875),   // UnderlyingSecurityXMLLen / UnderlyingSecurityXML
    (2072, 2073),   // EncodedUnderlyingEventTextLen / EncodedUnderlyingEventText
    (2074, 2075),   // EncodedLegEventTextLen / EncodedLegEventText
    (2111, 2112),   // EncodedAttachmentLen / EncodedAttachment
    (2179, 2180),   // EncodedLegOptionExpirationDescLen / EncodedLegOptionExpirationDesc
    (2287, 2288), // EncodedUnderlyingOptionExpirationDescLen / EncodedUnderlyingOptionExpirationDesc
    (2351, 2352), // EncodedComplianceTextLen / EncodedComplianceText
    (2372, 2371), // EncodedTradeContinuationTextLen / EncodedTradeContinuationText
    (2481, 2482), // EncodedMDStatisticDescLen / EncodedMDStatisticDesc
    (2494, 2493), // EncodedLegDocumentationTextLen / EncodedLegDocumentationText
    (2522, 2521), // EncodedWarningTextLen / EncodedWarningText
    (2637, 2638), // EncodedMiscFeeSubTypeDescLen / EncodedMiscFeeSubTypeDesc
    (2651, 2652), // EncodedCommissionDescLen / EncodedCommissionDesc
    (2665, 2666), // EncodedAllocCommissionDescLen / EncodedAllocCommissionDesc
    (2715, 2716), // EncodedFinancialInstrumentFullNameLen / EncodedFinancialInstrumentFullName
    (2718, 2719), // EncodedLegFinancialInstrumentFullNameLen / EncodedLegFinancialInstrumentFullName
    (2721, 2722), // EncodedUnderlyingFinancialInstrumentFullNameLen / EncodedUnderlyingFinancialInstrumentFullName
    (2797, 2798), // EncodedMatchExceptionTextLen / EncodedMatchExceptionText
    (2802, 2801), // EncodedReplaceTextLen / EncodedReplaceText
    (2809, 2808), // EncodedCancelTextLen / EncodedCancelText
    (2815, 2814), // EncodedPostTradePaymentDescLen / EncodedPostTradePaymentDesc
    (40004, 40005), // EncodedAdditionalTermBondDescLen / EncodedAdditionalTermBondDesc
    (40008, 40009), // EncodedAdditionalTermBondIssuerLen / EncodedAdditionalTermBondIssuer
    (40978, 40979), // EncodedLegStreamTextLen / EncodedLegStreamText
    (40980, 40981), // EncodedLegProvisionTextLen / EncodedLegProvisionText
    (40982, 40983), // EncodedStreamTextLen / EncodedStreamText
    (40984, 40985), // EncodedPaymentTextLen / EncodedPaymentText
    (40986, 40987), // EncodedProvisionTextLen / EncodedProvisionText
    (40988, 40989), // EncodedUnderlyingStreamTextLen / EncodedUnderlyingStreamText
    (41083, 41084), // EncodedDeliveryStreamCycleDescLen / EncodedDeliveryStreamCycleDesc
    (41101, 41102), // EncodedMarketDisruptionFallbackUnderlierSecurityDescLen / EncodedMarketDisruptionFallbackUnderlierSecurityDesc
    (41107, 41108), // EncodedExerciseDescLen / EncodedExerciseDesc
    (41256, 41257), // EncodedStreamCommodityDescLen / EncodedStreamCommodityDesc
    (41320, 41321), // EncodedLegAdditionalTermBondDescLen / EncodedLegAdditionalTermBondDesc
    (41324, 41325), // EncodedLegAdditionalTermBondIssuerLen / EncodedLegAdditionalTermBondIssuer
    (41458, 41459), // EncodedLegDeliveryStreamCycleDescLen / EncodedLegDeliveryStreamCycleDesc
    (41476, 41477), // EncodedLegMarketDisruptionFallbackUnderlierSecurityDescLen / EncodedLegMarketDisruptionFallbackUnderlierSecurityDesc
    (41482, 41483), // EncodedLegExerciseDescLen / EncodedLegExerciseDesc
    (41653, 41654), // EncodedLegStreamCommodityDescLen / EncodedLegStreamCommodityDesc
    (41710, 41711), // EncodedUnderlyingAdditionalTermBondDescLen / EncodedUnderlyingAdditionalTermBondDesc
    (41806, 41807), // EncodedUnderlyingDeliveryStreamCycleDescLen / EncodedUnderlyingDeliveryStreamCycleDesc
    (41811, 41812), // EncodedUnderlyingExerciseDescLen / EncodedUnderlyingExerciseDesc
    (41873, 41874), // EncodedUnderlyingMarketDisruptionFallbackUnderlierSecDescLen / EncodedUnderlyingMarketDisruptionFallbackUnderlierSecurityDesc
    (41969, 41970), // EncodedUnderlyingStreamCommodityDescLen / EncodedUnderlyingStreamCommodityDesc
    (42025, 42026), // EncodedUnderlyingAdditionalTermBondIssuerLen / EncodedUnderlyingAdditionalTermBondIssuer
    (42171, 42172), // EncodedUnderlyingProvisionTextLen / EncodedUnderlyingProvisionText
    (42451, 42452), // LegPaymentStreamFormulaImageLength / LegPaymentStreamFormulaImage
    (42652, 42653), // PaymentStreamFormulaImageLength / PaymentStreamFormulaImage
    (42947, 42948), // UnderlyingPaymentStreamFormulaImageLength / UnderlyingPaymentStreamFormulaImage
    (43109, 42684), // PaymentStreamFormulaLength / PaymentStreamFormula
    (43110, 42486), // LegPaymentStreamFormulaLength / LegPaymentStreamFormula
    (43111, 42982), // UnderlyingPaymentStreamFormulaLength / UnderlyingPaymentStreamFormula
];

/// Returns the `DATA` tag paired with `length_tag`, if any.
///
/// A FIX `DATA` field is a counted byte string whose content may legally
/// contain SOH and `=`; it is always immediately preceded by its `LENGTH`
/// field. Scanning such a value for SOH truncates it and injects phantom
/// fields from its payload, so the decoder frames it by the declared count
/// instead.
///
/// This is FIX **wire syntax** — a fixed, spec-defined tag set — not schema, so
/// resolving it must never require a dictionary lookup: `ironfix-tagvalue`
/// stays independent of `ironfix-dictionary`.
///
/// The arms below are the complete set of `LENGTH`/`DATA` pairs the FIX
/// specification defines from 4.0 through 5.0 SP2, FIXT.1.1 included — 83
/// pairs. Each was derived from the QuickFIX dictionary for its version by
/// taking, for every `type='DATA'` or `type='XMLDATA'` field, the
/// `type='LENGTH'` field that immediately precedes it in every message and
/// component carrying it; every `DATA` field resolves to exactly one `LENGTH`
/// field, no `LENGTH` field frames two different `DATA` fields, and no tag is
/// both. Tag numbers are never reused across FIX versions, so the union is a
/// single table rather than one table per version.
///
/// Two kinds of `DATA` field remain outside it, and both still fall back to an
/// SOH scan: user-defined fields (the 5000–9999 and 20000+ ranges FIX reserves
/// for bilateral use) and anything an Extension Pack adds after 5.0 SP2. The
/// first cannot be resolved from a fixed table at all — the tag number and its
/// type are a private agreement between two counterparties, not spec — so
/// closing that gap would need a per-session extension the caller supplies.
///
/// Written as a `match` rather than a table walk because `slice::get` is not
/// const-stable, so indexing a const array here would be unchecked indexing.
/// `LENGTH_DATA_PAIRS` cross-checks these arms in the tests so the two cannot
/// drift.
#[inline]
#[must_use]
pub(crate) const fn paired_data_tag(length_tag: u32) -> Option<u32> {
    // No `LENGTH` field is numbered below 90, so one comparison settles every
    // tag beneath it — including most of the session header — without entering
    // the table. `test_table_guards_match_the_table_minimums` pins the bound.
    if length_tag < FIRST_LENGTH_TAG {
        return None;
    }
    match length_tag {
        // FIX 4.0
        90 => Some(91), // SecureDataLen / SecureData
        93 => Some(89), // SignatureLength / Signature
        95 => Some(96), // RawDataLength / RawData
        // FIX 4.2
        212 => Some(213), // XmlDataLen / XmlData
        348 => Some(349), // EncodedIssuerLen / EncodedIssuer
        350 => Some(351), // EncodedSecurityDescLen / EncodedSecurityDesc
        352 => Some(353), // EncodedListExecInstLen / EncodedListExecInst
        354 => Some(355), // EncodedTextLen / EncodedText
        356 => Some(357), // EncodedSubjectLen / EncodedSubject
        358 => Some(359), // EncodedHeadlineLen / EncodedHeadline
        360 => Some(361), // EncodedAllocTextLen / EncodedAllocText
        362 => Some(363), // EncodedUnderlyingIssuerLen / EncodedUnderlyingIssuer
        364 => Some(365), // EncodedUnderlyingSecurityDescLen / EncodedUnderlyingSecurityDesc
        445 => Some(446), // EncodedListStatusTextLen / EncodedListStatusText
        // FIX 4.3
        618 => Some(619), // EncodedLegIssuerLen / EncodedLegIssuer
        621 => Some(622), // EncodedLegSecurityDescLen / EncodedLegSecurityDesc
        // FIX 5.0 SP1
        1184 => Some(1185), // SecurityXMLLen / SecurityXML
        1277 => Some(1278), // DerivativeEncodedIssuerLen / DerivativeEncodedIssuer
        1280 => Some(1281), // DerivativeEncodedSecurityDescLen / DerivativeEncodedSecurityDesc
        1282 => Some(1283), // DerivativeSecurityXMLLen / DerivativeSecurityXML
        1397 => Some(1398), // EncodedMktSegmDescLen / EncodedMktSegmDesc
        1401 => Some(1402), // EncryptedPasswordLen / EncryptedPassword
        1403 => Some(1404), // EncryptedNewPasswordLen / EncryptedNewPassword
        // FIX 5.0 SP2
        1468 => Some(1469), // EncodedSecurityListDescLen / EncodedSecurityListDesc
        1525 => Some(1527), // EncodedDocumentationTextLen / EncodedDocumentationText
        1578 => Some(1579), // EncodedEventTextLen / EncodedEventText
        1620 => Some(1621), // InstrumentScopeEncodedSecurityDescLen / InstrumentScopeEncodedSecurityDesc
        1664 => Some(1665), // EncodedRejectTextLen / EncodedRejectText
        1678 => Some(1697), // EncodedOptionExpirationDescLen / EncodedOptionExpirationDesc
        1733 => Some(1734), // EncodedFirmAllocTextLen / EncodedFirmAllocText
        1871 => Some(1872), // LegSecurityXMLLen / LegSecurityXML
        1874 => Some(1875), // UnderlyingSecurityXMLLen / UnderlyingSecurityXML
        2072 => Some(2073), // EncodedUnderlyingEventTextLen / EncodedUnderlyingEventText
        2074 => Some(2075), // EncodedLegEventTextLen / EncodedLegEventText
        2111 => Some(2112), // EncodedAttachmentLen / EncodedAttachment
        2179 => Some(2180), // EncodedLegOptionExpirationDescLen / EncodedLegOptionExpirationDesc
        2287 => Some(2288), // EncodedUnderlyingOptionExpirationDescLen / EncodedUnderlyingOptionExpirationDesc
        2351 => Some(2352), // EncodedComplianceTextLen / EncodedComplianceText
        2372 => Some(2371), // EncodedTradeContinuationTextLen / EncodedTradeContinuationText
        2481 => Some(2482), // EncodedMDStatisticDescLen / EncodedMDStatisticDesc
        2494 => Some(2493), // EncodedLegDocumentationTextLen / EncodedLegDocumentationText
        2522 => Some(2521), // EncodedWarningTextLen / EncodedWarningText
        2637 => Some(2638), // EncodedMiscFeeSubTypeDescLen / EncodedMiscFeeSubTypeDesc
        2651 => Some(2652), // EncodedCommissionDescLen / EncodedCommissionDesc
        2665 => Some(2666), // EncodedAllocCommissionDescLen / EncodedAllocCommissionDesc
        2715 => Some(2716), // EncodedFinancialInstrumentFullNameLen / EncodedFinancialInstrumentFullName
        2718 => Some(2719), // EncodedLegFinancialInstrumentFullNameLen / EncodedLegFinancialInstrumentFullName
        2721 => Some(2722), // EncodedUnderlyingFinancialInstrumentFullNameLen / EncodedUnderlyingFinancialInstrumentFullName
        2797 => Some(2798), // EncodedMatchExceptionTextLen / EncodedMatchExceptionText
        2802 => Some(2801), // EncodedReplaceTextLen / EncodedReplaceText
        2809 => Some(2808), // EncodedCancelTextLen / EncodedCancelText
        2815 => Some(2814), // EncodedPostTradePaymentDescLen / EncodedPostTradePaymentDesc
        40004 => Some(40005), // EncodedAdditionalTermBondDescLen / EncodedAdditionalTermBondDesc
        40008 => Some(40009), // EncodedAdditionalTermBondIssuerLen / EncodedAdditionalTermBondIssuer
        40978 => Some(40979), // EncodedLegStreamTextLen / EncodedLegStreamText
        40980 => Some(40981), // EncodedLegProvisionTextLen / EncodedLegProvisionText
        40982 => Some(40983), // EncodedStreamTextLen / EncodedStreamText
        40984 => Some(40985), // EncodedPaymentTextLen / EncodedPaymentText
        40986 => Some(40987), // EncodedProvisionTextLen / EncodedProvisionText
        40988 => Some(40989), // EncodedUnderlyingStreamTextLen / EncodedUnderlyingStreamText
        41083 => Some(41084), // EncodedDeliveryStreamCycleDescLen / EncodedDeliveryStreamCycleDesc
        41101 => Some(41102), // EncodedMarketDisruptionFallbackUnderlierSecurityDescLen / EncodedMarketDisruptionFallbackUnderlierSecurityDesc
        41107 => Some(41108), // EncodedExerciseDescLen / EncodedExerciseDesc
        41256 => Some(41257), // EncodedStreamCommodityDescLen / EncodedStreamCommodityDesc
        41320 => Some(41321), // EncodedLegAdditionalTermBondDescLen / EncodedLegAdditionalTermBondDesc
        41324 => Some(41325), // EncodedLegAdditionalTermBondIssuerLen / EncodedLegAdditionalTermBondIssuer
        41458 => Some(41459), // EncodedLegDeliveryStreamCycleDescLen / EncodedLegDeliveryStreamCycleDesc
        41476 => Some(41477), // EncodedLegMarketDisruptionFallbackUnderlierSecurityDescLen / EncodedLegMarketDisruptionFallbackUnderlierSecurityDesc
        41482 => Some(41483), // EncodedLegExerciseDescLen / EncodedLegExerciseDesc
        41653 => Some(41654), // EncodedLegStreamCommodityDescLen / EncodedLegStreamCommodityDesc
        41710 => Some(41711), // EncodedUnderlyingAdditionalTermBondDescLen / EncodedUnderlyingAdditionalTermBondDesc
        41806 => Some(41807), // EncodedUnderlyingDeliveryStreamCycleDescLen / EncodedUnderlyingDeliveryStreamCycleDesc
        41811 => Some(41812), // EncodedUnderlyingExerciseDescLen / EncodedUnderlyingExerciseDesc
        41873 => Some(41874), // EncodedUnderlyingMarketDisruptionFallbackUnderlierSecDescLen / EncodedUnderlyingMarketDisruptionFallbackUnderlierSecurityDesc
        41969 => Some(41970), // EncodedUnderlyingStreamCommodityDescLen / EncodedUnderlyingStreamCommodityDesc
        42025 => Some(42026), // EncodedUnderlyingAdditionalTermBondIssuerLen / EncodedUnderlyingAdditionalTermBondIssuer
        42171 => Some(42172), // EncodedUnderlyingProvisionTextLen / EncodedUnderlyingProvisionText
        42451 => Some(42452), // LegPaymentStreamFormulaImageLength / LegPaymentStreamFormulaImage
        42652 => Some(42653), // PaymentStreamFormulaImageLength / PaymentStreamFormulaImage
        42947 => Some(42948), // UnderlyingPaymentStreamFormulaImageLength / UnderlyingPaymentStreamFormulaImage
        43109 => Some(42684), // PaymentStreamFormulaLength / PaymentStreamFormula
        43110 => Some(42486), // LegPaymentStreamFormulaLength / LegPaymentStreamFormula
        43111 => Some(42982), // UnderlyingPaymentStreamFormulaLength / UnderlyingPaymentStreamFormula
        _ => None,
    }
}

/// Returns true if `tag` is a spec-defined `DATA` field.
///
/// The right-hand column of [`paired_data_tag`]: a value under one of these
/// tags may legally contain SOH and `=`, so it is only decodable when the
/// paired `LENGTH` field precedes it and declares its byte count. The encoder
/// uses this to refuse a `DATA` field written through the ordinary field path,
/// which would emit a frame no decoder can frame back.
///
/// Written as a `match` for the same reason as [`paired_data_tag`], and
/// cross-checked against `LENGTH_DATA_PAIRS` in the tests. It spans the same
/// versions and carries the same residual gap.
#[inline]
#[must_use]
pub(crate) const fn is_data_tag(tag: u32) -> bool {
    if tag < FIRST_DATA_TAG {
        return false;
    }
    matches!(
        tag,
        89 | 91
            | 96
            | 213
            | 349
            | 351
            | 353
            | 355
            | 357
            | 359
            | 361
            | 363
            | 365
            | 446
            | 619
            | 622
            | 1185
            | 1278
            | 1281
            | 1283
            | 1398
            | 1402
            | 1404
            | 1469
            | 1527
            | 1579
            | 1621
            | 1665
            | 1697
            | 1734
            | 1872
            | 1875
            | 2073
            | 2075
            | 2112
            | 2180
            | 2288
            | 2352
            | 2371
            | 2482
            | 2493
            | 2521
            | 2638
            | 2652
            | 2666
            | 2716
            | 2719
            | 2722
            | 2798
            | 2801
            | 2808
            | 2814
            | 40005
            | 40009
            | 40979
            | 40981
            | 40983
            | 40985
            | 40987
            | 40989
            | 41084
            | 41102
            | 41108
            | 41257
            | 41321
            | 41325
            | 41459
            | 41477
            | 41483
            | 41654
            | 41711
            | 41807
            | 41812
            | 41874
            | 41970
            | 42026
            | 42172
            | 42452
            | 42486
            | 42653
            | 42684
            | 42948
            | 42982
    )
}

/// A `DATA` field announced by the `LENGTH` field just consumed.
#[derive(Debug, Clone, Copy)]
struct PendingData {
    /// Tag of the `DATA` field expected next.
    data_tag: u32,
    /// Byte count declared by the `LENGTH` field.
    declared: usize,
}

/// Zero-copy FIX message decoder.
///
/// The decoder parses FIX messages from a byte buffer, extracting fields
/// as references to the original data without copying.
#[derive(Debug)]
pub struct Decoder<'a> {
    /// Input buffer.
    input: &'a [u8],
    /// Current position in the buffer.
    offset: usize,
    /// Whether to validate checksums.
    validate_checksum: bool,
    /// `DATA` field framing announced by the previous `LENGTH` field.
    pending_data: Option<PendingData>,
}

impl<'a> Decoder<'a> {
    /// Creates a new decoder for the given input buffer.
    ///
    /// # Arguments
    /// * `input` - The FIX message bytes to decode
    #[inline]
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            validate_checksum: true,
            pending_data: None,
        }
    }

    /// Sets whether to validate checksums during decoding.
    ///
    /// # Arguments
    /// * `validate` - Whether to validate checksums
    #[inline]
    #[must_use]
    pub const fn with_checksum_validation(mut self, validate: bool) -> Self {
        self.validate_checksum = validate;
        self
    }

    /// Decodes a complete FIX message from the buffer.
    ///
    /// The decoder can be called repeatedly to read consecutive messages out
    /// of a single buffer; the ranges stored in the returned [`RawMessage`]
    /// are relative to that message's own slice, not to the whole input.
    ///
    /// # Returns
    /// A `RawMessage` containing zero-copy references to the parsed fields.
    ///
    /// # Errors
    /// Returns `DecodeError` if the message is malformed or incomplete.
    /// Structural garbage after the last field is an error even when checksum
    /// validation is disabled — it is never silently discarded.
    pub fn decode(&mut self) -> Result<RawMessage<'a>, DecodeError> {
        let start_offset = self.offset;
        // Length/Data framing never carries across a message boundary.
        self.pending_data = None;

        // Parse BeginString (tag 8)
        let begin_string_field = self.next_field()?.ok_or(DecodeError::Incomplete)?;
        if begin_string_field.tag != 8 {
            return Err(DecodeError::InvalidBeginString);
        }
        let begin_string = self.value_range(start_offset, begin_string_field.value.len())?;

        // Parse BodyLength (tag 9)
        let body_length_field = self.next_field()?.ok_or(DecodeError::MissingBodyLength)?;
        if body_length_field.tag != 9 {
            return Err(DecodeError::MissingBodyLength);
        }
        // FIX types tag 9 as a `Length`: ASCII digits only. `str::parse` would
        // accept `9=+8`, and would additionally cost a UTF-8 validation pass
        // per frame, so the same strict digit fold used for every other length
        // in this file is used here.
        let body_length =
            parse_length(body_length_field.value).ok_or(DecodeError::InvalidBodyLength)?;

        // Record body start position. BodyLength (tag 9) is fully
        // attacker-controlled, so the end of the body is computed with checked
        // arithmetic here and then used to bound every field that follows: a
        // count-framed DATA value must not reach past it into the trailer.
        let body_start = self.offset;
        let body_end = body_start
            .checked_add(body_length)
            .ok_or(DecodeError::InvalidBodyLength)?;
        let limit = Some(body_end);

        // Parse MsgType (tag 35) - should be first field in body
        let msg_type_field = self
            .next_field_bounded(limit)?
            .ok_or(DecodeError::MissingMsgType)?;
        if msg_type_field.tag != 35 {
            return Err(DecodeError::MissingMsgType);
        }
        // An unrecognised code becomes `MsgType::Custom` in inline storage, so
        // this allocates nothing; an empty, over-long, or byte-illegal value is
        // `DecodeError::InvalidMsgType` rather than a truncated code that would
        // route the frame to the wrong handler.
        let msg_type: MsgType = msg_type_field.as_str()?.parse()?;

        // Collect all fields
        let mut fields: SmallVec<[FieldRef<'a>; 32]> = SmallVec::new();
        fields.push(begin_string_field);
        fields.push(body_length_field);
        fields.push(msg_type_field);

        // Parse remaining fields until checksum
        let mut checksum_field: Option<FieldRef<'a>> = None;
        // Offset of the first byte of the CheckSum (10) field, i.e. the end of
        // the body. Tracked explicitly so it stays correct for zero-padded tags
        // ("010=") that `parse_tag` folds numerically.
        let mut checksum_field_start = self.offset;
        loop {
            let field_start = self.offset;
            // `?` here is the point of the exercise: a missing `=`, a
            // non-numeric tag or an unterminated value is an error, not a
            // clean end of buffer.
            let Some(field) = self.next_field_bounded(limit)? else {
                break;
            };
            if field.tag == 10 {
                checksum_field = Some(field);
                checksum_field_start = field_start;
                break;
            }
            fields.push(field);
        }

        // The CheckSum field terminates every FIX frame, so its presence is
        // structural. `validate_checksum` governs whether its *value* is
        // verified, never whether the field must exist: without this a
        // count-framed DATA value that swallowed the trailer would still decode
        // cleanly on the validation-off path the engine uses.
        let checksum_ref = checksum_field.ok_or(DecodeError::Incomplete)?;

        // A well-formed frame declares exactly the bytes between the BodyLength
        // SOH and the start of the CheckSum field.
        if body_end != checksum_field_start {
            return Err(DecodeError::InvalidBodyLength);
        }

        if self.validate_checksum {
            let declared = parse_checksum(checksum_ref.value).ok_or_else(|| {
                DecodeError::InvalidFieldValue {
                    tag: 10,
                    reason: "invalid checksum format".to_string(),
                }
            })?;

            // Calculate checksum of everything before the checksum field
            let span = self.input.get(start_offset..checksum_field_start).ok_or(
                DecodeError::RangeOutOfBounds {
                    start: start_offset,
                    end: checksum_field_start,
                    buffer_len: self.input.len(),
                },
            )?;
            let calculated = calculate_checksum(span);

            if calculated != declared {
                return Err(DecodeError::ChecksumMismatch {
                    calculated,
                    declared,
                });
            }
        }

        // `RawMessage` ranges are relative to the message slice, so both
        // ranges are rebased by the offset this message started at.
        let body = rebase(body_start..body_end, start_offset, self.input.len())?;

        let buffer =
            self.input
                .get(start_offset..self.offset)
                .ok_or(DecodeError::RangeOutOfBounds {
                    start: start_offset,
                    end: self.offset,
                    buffer_len: self.input.len(),
                })?;

        RawMessage::new(buffer, begin_string, body, msg_type, fields)
    }

    /// Parses the next field from the buffer.
    ///
    /// A field is `tag=value<SOH>`. A value belonging to a spec-defined `DATA`
    /// tag is framed by the count declared in the `LENGTH` field immediately
    /// before it, so it may legally contain SOH and `=`.
    ///
    /// # Returns
    /// `Ok(None)` when the buffer is cleanly exhausted, `Ok(Some(field))`
    /// otherwise.
    ///
    /// Iterating with this method reads fields without any frame context, so a
    /// count-framed `DATA` value is bounded only by the buffer. Only
    /// [`Decoder::decode`] knows the frame's declared body end and can stop a
    /// count from reaching past it into the trailer.
    ///
    /// # Errors
    /// * [`DecodeError::InvalidTag`] - the tag is empty, non-numeric, too long,
    ///   or the field has no `=` delimiter.
    /// * [`DecodeError::UnterminatedField`] - the value is not terminated by
    ///   SOH.
    /// * [`DecodeError::InvalidDataLength`] - a `LENGTH` field declares a count
    ///   the remaining buffer cannot satisfy.
    /// * [`DecodeError::InvalidFieldValue`] - a `LENGTH` field value is not a
    ///   valid byte count.
    #[inline]
    pub fn next_field(&mut self) -> Result<Option<FieldRef<'a>>, DecodeError> {
        self.next_field_bounded(None)
    }

    /// Parses the next field, optionally bounded by the frame's declared body
    /// end.
    ///
    /// `body_limit` is the absolute offset of the first byte after the body,
    /// i.e. the start of the CheckSum field. A count-framed `DATA` value and
    /// its terminating SOH must both fall inside it.
    fn next_field_bounded(
        &mut self,
        body_limit: Option<usize>,
    ) -> Result<Option<FieldRef<'a>>, DecodeError> {
        // `offset` never exceeds `input.len()`, so a `None` here is exhaustion.
        let Some(remaining) = self.input.get(self.offset..) else {
            return Ok(None);
        };
        if remaining.is_empty() {
            return Ok(None);
        }

        // Find '=' delimiter using SIMD-accelerated search
        let eq_pos = memchr(EQUALS, remaining).ok_or_else(|| invalid_tag(remaining))?;
        let tag_bytes = remaining
            .get(..eq_pos)
            .ok_or_else(|| invalid_tag(remaining))?;
        let tag = parse_tag(tag_bytes).ok_or_else(|| invalid_tag(tag_bytes))?;

        let value_start = eq_pos
            .checked_add(1)
            .ok_or(DecodeError::UnterminatedField { tag })?;
        let value_bytes = remaining
            .get(value_start..)
            .ok_or(DecodeError::UnterminatedField { tag })?;

        // A `DATA` field announced by the preceding `LENGTH` field is consumed
        // by count. Taking the state unconditionally means it never leaks past
        // the field it describes.
        let counted = match self.pending_data.take() {
            Some(pending) if pending.data_tag == tag => Some(pending.declared),
            _ => None,
        };

        let value_len = match counted {
            Some(declared) => {
                let value_offset = self
                    .offset
                    .checked_add(value_start)
                    .ok_or(DecodeError::UnterminatedField { tag })?;
                // How many bytes this value may consume: the rest of the
                // buffer, further bounded by the frame's declared body end when
                // decoding a whole message. Without that bound a crafted count
                // swallows the CheckSum field, and the frame still decodes
                // whenever checksum validation is off.
                let available = match body_limit {
                    // A field starting at or past the declared body end means
                    // BodyLength disagrees with the frame's actual layout.
                    Some(limit) => limit
                        .checked_sub(value_offset)
                        .ok_or(DecodeError::InvalidBodyLength)?
                        .min(value_bytes.len()),
                    None => value_bytes.len(),
                };
                // `declared` is attacker-controlled. The terminating SOH sits at
                // index `declared`, so it must fall inside `available`; probing
                // it beats sizing anything from the declared count.
                if declared >= available || value_bytes.get(declared) != Some(&SOH) {
                    return Err(DecodeError::InvalidDataLength {
                        data_tag: tag,
                        declared,
                        available,
                    });
                }
                declared
            }
            None => memchr(SOH, value_bytes).ok_or(DecodeError::UnterminatedField { tag })?,
        };

        let value = value_bytes
            .get(..value_len)
            .ok_or(DecodeError::UnterminatedField { tag })?;

        // Consume `tag=value<SOH>`.
        let consumed = value_start
            .checked_add(value_len)
            .and_then(|end| end.checked_add(1))
            .ok_or(DecodeError::UnterminatedField { tag })?;
        self.offset = self
            .offset
            .checked_add(consumed)
            .ok_or(DecodeError::UnterminatedField { tag })?;

        // Remember a `LENGTH` field so the paired `DATA` field is framed by
        // count rather than by an SOH scan.
        if let Some(data_tag) = paired_data_tag(tag) {
            let declared = parse_length(value).ok_or_else(|| invalid_length(tag))?;
            self.pending_data = Some(PendingData { data_tag, declared });
        }

        Ok(Some(FieldRef::new(tag, value)))
    }

    /// Returns the buffer-relative range of the value of the field just
    /// consumed, for a message that starts at `message_start`.
    ///
    /// The decoder has consumed `tag=value<SOH>`, so the value ends one byte
    /// before the current offset.
    fn value_range(
        &self,
        message_start: usize,
        value_len: usize,
    ) -> Result<Range<usize>, DecodeError> {
        let out_of_bounds = || DecodeError::RangeOutOfBounds {
            start: message_start,
            end: self.offset,
            buffer_len: self.input.len(),
        };
        let value_end = self.offset.checked_sub(1).ok_or_else(out_of_bounds)?;
        let value_start = value_end.checked_sub(value_len).ok_or_else(out_of_bounds)?;
        rebase(value_start..value_end, message_start, self.input.len())
    }

    /// Returns the current offset in the buffer.
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the remaining bytes in the buffer.
    #[inline]
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        // `offset` is only ever advanced to a position inside the buffer.
        self.input.get(self.offset..).unwrap_or(&[])
    }

    /// Returns true if the buffer has been fully consumed.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.offset >= self.input.len()
    }

    /// Resets the decoder to the beginning of the buffer.
    #[inline]
    pub fn reset(&mut self) {
        self.offset = 0;
        self.pending_data = None;
    }
}

/// Rebases an absolute range into one relative to `message_start`.
#[inline]
fn rebase(
    range: Range<usize>,
    message_start: usize,
    buffer_len: usize,
) -> Result<Range<usize>, DecodeError> {
    let out_of_bounds = || DecodeError::RangeOutOfBounds {
        start: range.start,
        end: range.end,
        buffer_len,
    };
    let start = range
        .start
        .checked_sub(message_start)
        .ok_or_else(out_of_bounds)?;
    let end = range
        .end
        .checked_sub(message_start)
        .ok_or_else(out_of_bounds)?;
    Ok(start..end)
}

/// Builds a [`DecodeError::InvalidTag`] with a bounded diagnostic.
///
/// Kept out of line: it allocates, and it is called from `ok_or_else` closures
/// inside `next_field`, the hottest function in the crate. Inlining it would
/// pull the UTF-8 validation and allocator sequence into the scan loop's
/// instruction-cache footprint.
#[cold]
#[inline(never)]
fn invalid_tag(bytes: &[u8]) -> DecodeError {
    let shown = bytes.get(..MAX_TAG_DIAGNOSTIC_LEN).unwrap_or(bytes);
    DecodeError::InvalidTag(String::from_utf8_lossy(shown).into_owned())
}

/// Builds a [`DecodeError::InvalidFieldValue`] for an unparseable `LENGTH`
/// field value.
///
/// Out of line for the same reason as [`invalid_tag`].
#[cold]
#[inline(never)]
fn invalid_length(tag: u32) -> DecodeError {
    DecodeError::InvalidFieldValue {
        tag,
        reason: "length field value is not a valid byte count".to_string(),
    }
}

/// Parses a tag number from ASCII bytes.
///
/// # Arguments
/// * `bytes` - The ASCII bytes representing the tag number
///
/// # Returns
/// The parsed tag number, or `None` if invalid.
#[inline]
fn parse_tag(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > MAX_TAG_DIGITS {
        return None;
    }

    let mut result: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        result = result.checked_mul(10)?.checked_add(u32::from(b - b'0'))?;
    }

    Some(result)
}

/// Parses a FIX `Length` field value (a byte count) from ASCII bytes.
///
/// Used for `BodyLength` (tag 9) and for every `LENGTH` field that frames a
/// paired `DATA` field. FIX defines these as unsigned integers, so a leading
/// sign, a space, or any other non-digit byte is rejected rather than coerced.
///
/// # Returns
/// The declared count, or `None` if the value is empty, non-numeric, too long,
/// or overflows `usize`.
#[inline]
fn parse_length(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() || bytes.len() > MAX_LENGTH_DIGITS {
        return None;
    }

    let mut result: usize = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        result = result.checked_mul(10)?.checked_add(usize::from(b - b'0'))?;
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ironfix_core::error::MsgTypeError;
    use ironfix_core::message::MSG_TYPE_MAX_LEN;

    /// Every tag number the pair table can be asked about, as an iterator.
    ///
    /// The two disjoint bands the table occupies, padded on both sides: the
    /// classic FIX range and the 40000+ range FIX 5.0 SP2 uses for the
    /// derivatives extension.
    fn candidate_tags() -> impl Iterator<Item = u32> {
        (1..=3_000u32).chain(39_000..=44_000u32)
    }

    /// Builds a well-formed frame around `body` with a valid trailing checksum.
    fn build_frame(body: &[u8]) -> Vec<u8> {
        build_frame_with_begin_string(b"FIX.4.4", body)
    }

    /// Builds a well-formed frame with an arbitrary BeginString value.
    fn build_frame_with_begin_string(begin_string: &[u8], body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(body.len() + 32);
        msg.extend_from_slice(b"8=");
        msg.extend_from_slice(begin_string);
        msg.push(SOH);
        msg.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
        msg.extend_from_slice(body);
        let sum: u64 = msg.iter().map(|&b| u64::from(b)).sum();
        msg.extend_from_slice(format!("10={:03}\x01", (sum % 256) as u8).as_bytes());
        msg
    }

    #[test]
    fn test_parse_tag() {
        assert_eq!(parse_tag(b"8"), Some(8));
        assert_eq!(parse_tag(b"35"), Some(35));
        assert_eq!(parse_tag(b"12345"), Some(12345));
        assert_eq!(parse_tag(b""), None);
        assert_eq!(parse_tag(b"abc"), None);
        assert_eq!(parse_tag(b"12a"), None);
    }

    #[test]
    fn test_parse_length_rejects_hostile_values() {
        assert_eq!(parse_length(b"0"), Some(0));
        assert_eq!(parse_length(b"7"), Some(7));
        assert_eq!(parse_length(b""), None);
        assert_eq!(parse_length(b"-1"), None);
        assert_eq!(parse_length(b"1a"), None);
        // More digits than a byte count can plausibly need.
        assert_eq!(parse_length(b"99999999999999999999"), None);
    }

    #[test]
    fn test_paired_data_tag_covers_spec_pairs() {
        // One from each version band the table spans.
        assert_eq!(paired_data_tag(95), Some(96)); // 4.0
        assert_eq!(paired_data_tag(93), Some(89)); // 4.0, length tag above data tag
        assert_eq!(paired_data_tag(354), Some(355)); // 4.2
        assert_eq!(paired_data_tag(621), Some(622)); // 4.3
        assert_eq!(paired_data_tag(1397), Some(1398)); // 5.0 SP1
        assert_eq!(paired_data_tag(1678), Some(1697)); // 5.0 SP2, non-adjacent
        assert_eq!(paired_data_tag(43111), Some(42982)); // 5.0 SP2, five digits
        assert_eq!(paired_data_tag(35), None);
        // No tag is both a length tag and a data tag.
        for (_, data_tag) in LENGTH_DATA_PAIRS {
            assert_eq!(paired_data_tag(data_tag), None);
        }
    }

    #[test]
    fn test_paired_data_tag_matches_the_spec_table() {
        // The reference table is the complete `type='DATA'`/`type='XMLDATA'`
        // set from FIX 4.0 through 5.0 SP2. Cross-checking it against the match
        // arms catches drift in either.
        for (length_tag, data_tag) in LENGTH_DATA_PAIRS {
            assert_eq!(paired_data_tag(length_tag), Some(data_tag));
        }
        // Nothing outside the table is treated as a length tag.
        let length_tags: Vec<u32> = LENGTH_DATA_PAIRS.iter().map(|(len, _)| *len).collect();
        for tag in candidate_tags() {
            if !length_tags.contains(&tag) {
                assert_eq!(paired_data_tag(tag), None, "tag {tag} must not be paired");
            }
        }
    }

    #[test]
    fn test_length_data_pairs_is_a_bijection() {
        // A length tag framing two data fields, or a data field claimed by two
        // length tags, would make the framing ambiguous.
        let length_tags: Vec<u32> = LENGTH_DATA_PAIRS.iter().map(|(len, _)| *len).collect();
        let data_tags: Vec<u32> = LENGTH_DATA_PAIRS.iter().map(|(_, data)| *data).collect();
        for (index, tag) in length_tags.iter().enumerate() {
            assert_eq!(
                length_tags.iter().position(|other| other == tag),
                Some(index),
                "length tag {tag} appears twice"
            );
            assert!(
                !data_tags.contains(tag),
                "tag {tag} is both length and data"
            );
        }
        for (index, tag) in data_tags.iter().enumerate() {
            assert_eq!(
                data_tags.iter().position(|other| other == tag),
                Some(index),
                "data tag {tag} appears twice"
            );
        }
    }

    #[test]
    fn test_table_guards_match_the_table_minimums() {
        // Both lookups short-circuit below their bound, so a pair added beneath
        // one would be silently unreachable.
        assert_eq!(
            LENGTH_DATA_PAIRS.iter().map(|(len, _)| *len).min(),
            Some(FIRST_LENGTH_TAG)
        );
        assert_eq!(
            LENGTH_DATA_PAIRS.iter().map(|(_, data)| *data).min(),
            Some(FIRST_DATA_TAG)
        );
    }

    #[test]
    fn test_next_field() {
        let input = b"8=FIX.4.4\x019=5\x0135=0\x01";
        let mut decoder = Decoder::new(input);

        let Ok(Some(field1)) = decoder.next_field() else {
            panic!("first field must parse");
        };
        assert_eq!(field1.tag, 8);
        assert_eq!(field1.as_str(), Ok("FIX.4.4"));

        let Ok(Some(field2)) = decoder.next_field() else {
            panic!("second field must parse");
        };
        assert_eq!(field2.tag, 9);
        assert_eq!(field2.as_str(), Ok("5"));

        let Ok(Some(field3)) = decoder.next_field() else {
            panic!("third field must parse");
        };
        assert_eq!(field3.tag, 35);
        assert_eq!(field3.as_str(), Ok("0"));

        assert!(matches!(decoder.next_field(), Ok(None)));
    }

    #[test]
    fn test_decoder_empty() {
        let mut decoder = Decoder::new(b"");
        assert!(matches!(decoder.next_field(), Ok(None)));
        assert!(decoder.is_empty());
    }

    #[test]
    fn test_next_field_missing_soh_is_unterminated_field() {
        let input = b"8=FIX.4.4";
        let mut decoder = Decoder::new(input);
        assert_eq!(
            decoder.next_field().err(),
            Some(DecodeError::UnterminatedField { tag: 8 })
        );
    }

    #[test]
    fn test_next_field_non_numeric_tag_is_invalid_tag() {
        let mut decoder = Decoder::new(b"abc=1\x01");
        let error = decoder.next_field().err();
        assert!(matches!(error, Some(DecodeError::InvalidTag(_))));
        assert_ne!(error, Some(DecodeError::Incomplete));
    }

    #[test]
    fn test_next_field_missing_equals_is_invalid_tag() {
        let mut decoder = Decoder::new(b"garbage-no-equals\x01");
        let error = decoder.next_field().err();
        assert!(matches!(error, Some(DecodeError::InvalidTag(_))));
        assert_ne!(error, Some(DecodeError::Incomplete));
    }

    #[test]
    fn test_next_field_invalid_tag_diagnostic_is_bounded() {
        let mut input = vec![b'x'; 4096];
        input.push(SOH);
        let mut decoder = Decoder::new(&input);
        match decoder.next_field() {
            Err(DecodeError::InvalidTag(text)) => {
                assert!(text.len() <= MAX_TAG_DIAGNOSTIC_LEN);
            }
            other => panic!("expected InvalidTag, got {other:?}"),
        }
    }

    #[test]
    fn test_next_field_empty_tag_is_invalid_tag() {
        let mut decoder = Decoder::new(b"=value\x01");
        assert!(matches!(
            decoder.next_field(),
            Err(DecodeError::InvalidTag(_))
        ));
    }

    /// Builds a frame with the given BodyLength text (which may be hostile) and
    /// a valid trailing checksum over the resulting bytes.
    fn frame_with_body_length(body_length_text: &str, body_length_tag: &str) -> Vec<u8> {
        let body = b"35=0\x0149=A\x0156=B\x0134=1\x0152=20240329-12:00:00\x01";
        let mut msg = Vec::new();
        msg.extend_from_slice(b"8=FIX.4.4\x01");
        msg.extend_from_slice(format!("{body_length_tag}={body_length_text}\x01").as_bytes());
        msg.extend_from_slice(body);
        let sum: u64 = msg.iter().map(|&b| u64::from(b)).sum();
        msg.extend_from_slice(format!("10={:03}\x01", (sum % 256) as u8).as_bytes());
        msg
    }

    #[test]
    fn test_decode_body_length_overflow_does_not_panic() {
        let msg = frame_with_body_length(&usize::MAX.to_string(), "9");
        assert_eq!(
            Decoder::new(&msg).decode().err(),
            Some(DecodeError::InvalidBodyLength)
        );
    }

    #[test]
    fn test_decode_body_length_overflow_zero_padded_tag() {
        // `parse_tag` folds digits numerically, so "009" is tag 9 here too.
        let msg = frame_with_body_length(&usize::MAX.to_string(), "009");
        assert_eq!(
            Decoder::new(&msg).decode().err(),
            Some(DecodeError::InvalidBodyLength)
        );
    }

    #[test]
    fn test_decode_rejects_body_length_mismatch() {
        let msg = frame_with_body_length("5", "9");
        assert_eq!(
            Decoder::new(&msg).decode().err(),
            Some(DecodeError::InvalidBodyLength)
        );
    }

    #[test]
    fn test_decode_accepts_correct_body_length() {
        let body = b"35=0\x0149=A\x0156=B\x0134=1\x0152=20240329-12:00:00\x01";
        let msg = frame_with_body_length(&body.len().to_string(), "9");
        let Ok(decoded) = Decoder::new(&msg).decode() else {
            panic!("valid frame must decode");
        };
        assert_eq!(*decoded.msg_type(), MsgType::Heartbeat);
    }

    #[test]
    fn test_decode_unrecognised_msg_type_becomes_custom() {
        // The whole point of the bounded `Custom`: a vendor-specific MsgType
        // decodes into inline storage instead of a per-message heap allocation.
        let body = b"35=U7\x0149=A\x0156=B\x0134=1\x01";
        let msg = build_frame(body);
        let Ok(decoded) = Decoder::new(&msg).decode() else {
            panic!("a representable custom MsgType must decode");
        };
        assert_eq!(decoded.msg_type().as_str(), "U7");
        assert!(matches!(decoded.msg_type(), MsgType::Custom(_)));
    }

    #[test]
    fn test_decode_msg_type_at_the_bound_is_accepted() {
        let body = b"35=U9999999\x0149=A\x0156=B\x0134=1\x01";
        let msg = build_frame(body);
        let Ok(decoded) = Decoder::new(&msg).decode() else {
            panic!("a MSG_TYPE_MAX_LEN-byte MsgType must decode");
        };
        assert_eq!(decoded.msg_type().as_str(), "U9999999");
    }

    #[test]
    fn test_decode_over_long_msg_type_is_typed_error() {
        // One byte past MSG_TYPE_MAX_LEN. Truncating it would hand the session
        // layer a different, valid MsgType.
        let body = b"35=U99999999\x0149=A\x0156=B\x0134=1\x01";
        let msg = build_frame(body);
        assert_eq!(
            Decoder::new(&msg).decode().err(),
            Some(DecodeError::InvalidMsgType(MsgTypeError::TooLong {
                len: 9,
                max_len: MSG_TYPE_MAX_LEN,
            }))
        );
    }

    #[test]
    fn test_decode_empty_msg_type_is_typed_error() {
        let body = b"35=\x0149=A\x0156=B\x0134=1\x01";
        let msg = build_frame(body);
        assert_eq!(
            Decoder::new(&msg).decode().err(),
            Some(DecodeError::InvalidMsgType(MsgTypeError::Empty))
        );
    }

    #[test]
    fn test_decode_msg_type_with_embedded_equals_is_accepted() {
        // `35=A=B` scans as the value "A=B": a field splits on its *first* `=`
        // only, and `=` is legal inside a FIX value, so this is a valid
        // (bilateral) MsgType that must round-trip verbatim rather than be
        // rejected. It is written back into tag 35 unchanged.
        let body = b"35=A=B\x0149=A\x0156=B\x0134=1\x01";
        let msg = build_frame(body);
        let Ok(decoded) = Decoder::new(&msg).decode() else {
            panic!("a MsgType containing `=` must decode");
        };
        assert_eq!(decoded.msg_type().as_str(), "A=B");
    }

    #[test]
    fn test_decode_checksum_field_start_with_padded_tag() {
        // Trailing checksum written as "010=" must still checksum the same span.
        let body = b"35=0\x0149=A\x0156=B\x0134=1\x0152=20240329-12:00:00\x01";
        let mut msg = Vec::new();
        msg.extend_from_slice(b"8=FIX.4.4\x01");
        msg.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
        msg.extend_from_slice(body);
        let sum: u64 = msg.iter().map(|&b| u64::from(b)).sum();
        msg.extend_from_slice(format!("010={:03}\x01", (sum % 256) as u8).as_bytes());
        assert!(Decoder::new(&msg).decode().is_ok());
    }

    #[test]
    fn test_decode_mid_body_checksum_out_of_range_is_rejected() {
        // A duplicate/injected `10=624` must not overflow the checksum parser.
        let body = b"35=0\x0110=624\x0149=A\x01";
        let mut msg = Vec::new();
        msg.extend_from_slice(b"8=FIX.4.4\x01");
        msg.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
        msg.extend_from_slice(body);
        msg.extend_from_slice(b"10=000\x01");
        assert!(Decoder::new(&msg).decode().is_err());
    }

    #[test]
    fn test_decode_two_consecutive_frames_are_both_correct() {
        let first_body: &[u8] = b"35=0\x0149=A\x0156=B\x01";
        let second_body: &[u8] = b"35=A\x0149=CCCC\x0156=DDDD\x01";
        let first_frame = build_frame(first_body);
        let second_frame = build_frame(second_body);

        let mut input = first_frame.clone();
        input.extend_from_slice(&second_frame);

        let mut decoder = Decoder::new(&input);

        let Ok(first) = decoder.decode() else {
            panic!("first frame must decode");
        };
        assert_eq!(first.begin_string(), Ok("FIX.4.4"));
        assert_eq!(*first.msg_type(), MsgType::Heartbeat);
        assert_eq!(first.body(), Ok(first_body));
        assert_eq!(first.len(), first_frame.len());

        // The second frame is where absolute ranges used to index out of
        // bounds and abort the process.
        let Ok(second) = decoder.decode() else {
            panic!("second frame must decode");
        };
        assert_eq!(second.begin_string(), Ok("FIX.4.4"));
        assert_eq!(*second.msg_type(), MsgType::Logon);
        assert_eq!(second.body(), Ok(second_body));
        assert_eq!(second.len(), second_frame.len());

        // Both bodies must start after "8=FIX.4.4<SOH>9=<len><SOH>".
        let expected_start = 10 + format!("9={}\x01", second_body.len()).len();
        assert_eq!(
            *second.body_range(),
            expected_start..expected_start + second_body.len()
        );

        assert!(decoder.is_empty());
    }

    #[test]
    fn test_decode_begin_string_invalid_utf8_is_typed_error() {
        let msg = build_frame_with_begin_string(b"FIX\xff\xfe4", b"35=0\x01");
        let Ok(decoded) = Decoder::new(&msg).decode() else {
            panic!("frame with non-utf8 BeginString still frames");
        };
        assert!(matches!(
            decoded.begin_string(),
            Err(DecodeError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn test_decode_raw_data_with_embedded_soh_and_equals_roundtrips() {
        // 7 bytes carrying both an SOH and an '=' inside the value.
        let raw_data: &[u8] = b"a\x01b=c\x01d";
        let mut body = Vec::new();
        body.extend_from_slice(b"35=A\x01");
        body.extend_from_slice(b"95=7\x01");
        body.extend_from_slice(b"96=");
        body.extend_from_slice(raw_data);
        body.push(SOH);
        body.extend_from_slice(b"58=after\x01");
        let msg = build_frame(&body);

        let Ok(decoded) = Decoder::new(&msg).decode() else {
            panic!("frame with RawData must decode");
        };
        let Some(field) = decoded.get_field(96) else {
            panic!("RawData field must be present");
        };
        assert_eq!(field.value, raw_data);
        // No phantom fields injected from inside the payload.
        assert!(decoded.get_field(98).is_none());
        assert_eq!(decoded.get_field_str(58), Some("after"));
        // 8, 9, 35, 95, 96, 58
        assert_eq!(decoded.field_count(), 6);
    }

    #[test]
    fn test_decode_post_fix44_data_field_with_embedded_soh_roundtrips() {
        // 1397/1398 EncodedMktSegmDescLen / EncodedMktSegmDesc, added in
        // FIX 5.0 SP1: before the table covered it the payload's SOH split the
        // value and "9=999" was read as a second BodyLength field.
        let encoded: &[u8] = b"seg\x019=999\x01x";
        let mut body = Vec::new();
        body.extend_from_slice(b"35=A\x01");
        body.extend_from_slice(format!("1397={}\x01", encoded.len()).as_bytes());
        body.extend_from_slice(b"1398=");
        body.extend_from_slice(encoded);
        body.push(SOH);
        body.extend_from_slice(b"58=after\x01");
        let msg = build_frame(&body);

        let Ok(decoded) = Decoder::new(&msg).decode() else {
            panic!("frame with EncodedMktSegmDesc must decode");
        };
        assert_eq!(decoded.get_field(1398).map(|f| f.value), Some(encoded));
        assert_eq!(decoded.get_field_str(58), Some("after"));
        // 8, 9, 35, 1397, 1398, 58 — no phantom field from inside the payload.
        assert_eq!(decoded.field_count(), 6);
    }

    #[test]
    fn test_decode_five_digit_data_field_with_embedded_soh_roundtrips() {
        // 43111/42982 UnderlyingPaymentStreamFormulaLength /
        // UnderlyingPaymentStreamFormula: a FIX 5.0 SP2 pair in the 40000+
        // band whose length tag is numerically above its data tag.
        let formula: &[u8] = b"<f a=\"1\"/>\x01<g/>";
        let mut body = Vec::new();
        body.extend_from_slice(b"35=A\x01");
        body.extend_from_slice(format!("43111={}\x01", formula.len()).as_bytes());
        body.extend_from_slice(b"42982=");
        body.extend_from_slice(formula);
        body.push(SOH);
        body.extend_from_slice(b"58=after\x01");
        let msg = build_frame(&body);

        let Ok(decoded) = Decoder::new(&msg).decode() else {
            panic!("frame with UnderlyingPaymentStreamFormula must decode");
        };
        assert_eq!(decoded.get_field(42982).map(|f| f.value), Some(formula));
        assert_eq!(decoded.get_field_str(58), Some("after"));
        assert_eq!(decoded.field_count(), 6);
    }

    #[test]
    fn test_decode_post_fix44_data_field_truncated_payload_is_typed_error() {
        // The hardening the table buys applies to the new pairs too: a count
        // reaching past the body is rejected, not silently clamped.
        let msg = build_frame(b"35=A\x011401=20\x011402=abc\x01");

        assert_eq!(
            Decoder::new(&msg).decode().err(),
            Some(DecodeError::InvalidDataLength {
                data_tag: 1402,
                declared: 20,
                available: 4,
            })
        );
    }

    #[test]
    fn test_decode_raw_data_truncated_payload_is_typed_error() {
        // Declares 20 bytes but only 3 are present before the terminator.
        let mut body = Vec::new();
        body.extend_from_slice(b"35=A\x0195=20\x0196=abc\x01");
        let msg = build_frame(&body);

        assert_eq!(
            Decoder::new(&msg).decode().err(),
            // `available` is scoped to the frame's declared body, not to the
            // rest of the buffer: 4 bytes of body remain after "96=".
            Some(DecodeError::InvalidDataLength {
                data_tag: 96,
                declared: 20,
                available: 4,
            })
        );
    }

    #[test]
    fn test_decode_data_count_cannot_swallow_the_checksum_field() {
        // A count-framed DATA value whose declared length reaches past the body
        // and lands on the SOH before "10=" would consume the trailer: no tag 10
        // is then found, and with checksum validation off the frame would decode
        // with the trailer bytes injected into the DATA value. The count is
        // bounded by the declared body end, so this is rejected on both paths.
        // BodyLength counts "35=A|95=8|96=x|" = 15 bytes, and the checksum is
        // correct for the frame, so nothing but the count is malformed.
        let body: &[u8] = b"35=A\x0195=8\x0196=x\x01";
        let msg = build_frame(body);

        for validate in [true, false] {
            let result = Decoder::new(&msg)
                .with_checksum_validation(validate)
                .decode();
            assert!(
                matches!(
                    result,
                    Err(DecodeError::InvalidDataLength { data_tag: 96, .. })
                ),
                "validate_checksum={validate} must reject the swallowed trailer, got {result:?}"
            );
        }
    }

    #[test]
    fn test_decode_missing_checksum_field_is_error_without_validation() {
        // The CheckSum field is structural: a frame that never emits tag 10 must
        // be rejected even when checksum validation is disabled.
        let mut msg = Vec::new();
        msg.extend_from_slice(b"8=FIX.4.4\x01");
        msg.extend_from_slice(b"9=5\x01");
        msg.extend_from_slice(b"35=0\x01");

        assert_eq!(
            Decoder::new(&msg)
                .with_checksum_validation(false)
                .decode()
                .err(),
            Some(DecodeError::Incomplete)
        );
    }

    #[test]
    fn test_decode_raw_data_hostile_length_is_typed_error() {
        // A count far beyond the buffer must be rejected by a bounds probe,
        // never by allocating `declared` bytes.
        let mut body = Vec::new();
        body.extend_from_slice(b"35=A\x0195=4294967295\x0196=abc\x01");
        let msg = build_frame(&body);

        assert!(matches!(
            Decoder::new(&msg).decode(),
            Err(DecodeError::InvalidDataLength {
                data_tag: 96,
                declared: 4_294_967_295,
                ..
            })
        ));
    }

    #[test]
    fn test_decode_raw_data_length_mismatch_not_on_soh_is_rejected() {
        // Declares 2 bytes for a 3-byte payload: the declared end is not SOH.
        let msg = build_frame(b"35=A\x0195=2\x0196=abc\x01");
        assert!(matches!(
            Decoder::new(&msg).decode(),
            Err(DecodeError::InvalidDataLength { data_tag: 96, .. })
        ));
    }

    #[test]
    fn test_decode_non_numeric_length_field_is_typed_error() {
        let msg = build_frame(b"35=A\x0195=abc\x0196=x\x01");
        assert!(matches!(
            Decoder::new(&msg).decode(),
            Err(DecodeError::InvalidFieldValue { tag: 95, .. })
        ));
    }

    #[test]
    fn test_decode_length_field_not_followed_by_its_data_field_parses_normally() {
        // Framing by count only applies to the paired DATA tag; anything else
        // falls back to the normal SOH scan without fabricating a field.
        let msg = build_frame(b"35=A\x0195=7\x0158=text\x01");
        let Ok(decoded) = Decoder::new(&msg).decode() else {
            panic!("frame must decode");
        };
        assert_eq!(decoded.get_field_str(58), Some("text"));
        assert_eq!(decoded.get_field_str(95), Some("7"));
    }

    #[test]
    fn test_decode_zero_length_data_field_is_accepted() {
        let msg = build_frame(b"35=A\x0195=0\x0196=\x0158=after\x01");
        let Ok(decoded) = Decoder::new(&msg).decode() else {
            panic!("frame with empty RawData must decode");
        };
        let Some(field) = decoded.get_field(96) else {
            panic!("RawData field must be present");
        };
        assert!(field.value.is_empty());
        assert_eq!(decoded.get_field_str(58), Some("after"));
    }

    #[test]
    fn test_decode_trailing_garbage_without_checksum_validation_is_error() {
        let mut msg = b"8=FIX.4.4\x019=5\x0135=0\x01".to_vec();
        msg.extend_from_slice(b"garbage-no-equals");

        let result = Decoder::new(&msg).with_checksum_validation(false).decode();
        assert!(matches!(result, Err(DecodeError::InvalidTag(_))));
    }

    #[test]
    fn test_decode_trailing_unterminated_field_without_checksum_validation_is_error() {
        let mut msg = b"8=FIX.4.4\x019=5\x0135=0\x01".to_vec();
        msg.extend_from_slice(b"58=unterminated");

        let result = Decoder::new(&msg).with_checksum_validation(false).decode();
        assert_eq!(
            result.err(),
            Some(DecodeError::UnterminatedField { tag: 58 })
        );
    }

    #[test]
    fn test_decode_body_length_with_leading_sign_is_rejected() {
        // FIX types tag 9 as a digits-only Length. `str::parse` accepted "+8",
        // so a frame whose declared length carried a sign framed cleanly.
        for text in ["+8", "-8", " 8", "8 ", "0x8", ""] {
            let msg = frame_with_body_length(text, "9");
            assert_eq!(
                Decoder::new(&msg).decode().err(),
                Some(DecodeError::InvalidBodyLength),
                "9={text:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_decode_body_length_non_utf8_is_invalid_body_length() {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"8=FIX.4.4\x01");
        msg.extend_from_slice(b"9=\xff\xfe\x01");
        msg.extend_from_slice(b"35=0\x0110=000\x01");
        assert_eq!(
            Decoder::new(&msg).decode().err(),
            Some(DecodeError::InvalidBodyLength)
        );
    }

    #[test]
    fn test_decode_body_length_with_too_many_digits_is_rejected() {
        let msg = frame_with_body_length("00000000008", "9");
        assert_eq!(
            Decoder::new(&msg).decode().err(),
            Some(DecodeError::InvalidBodyLength)
        );
    }

    #[test]
    fn test_decode_first_tag_not_8_is_invalid_begin_string() {
        let msg = b"9=5\x018=FIX.4.4\x0135=0\x0110=000\x01";
        assert_eq!(
            Decoder::new(msg).decode().err(),
            Some(DecodeError::InvalidBeginString)
        );
    }

    #[test]
    fn test_decode_second_tag_not_9_is_missing_body_length() {
        let msg = b"8=FIX.4.4\x0135=0\x0110=000\x01";
        assert_eq!(
            Decoder::new(msg).decode().err(),
            Some(DecodeError::MissingBodyLength)
        );
    }

    #[test]
    fn test_decode_body_length_only_is_missing_msg_type() {
        // Nothing after the header at all: the body is empty and there is no
        // third field to read a MsgType from.
        let msg = b"8=FIX.4.4\x019=0\x01";
        assert_eq!(
            Decoder::new(msg).decode().err(),
            Some(DecodeError::MissingMsgType)
        );
    }

    #[test]
    fn test_decode_third_tag_not_35_is_missing_msg_type() {
        let body = b"49=A\x0135=0\x01";
        let msg = build_frame(body);
        assert_eq!(
            Decoder::new(&msg).decode().err(),
            Some(DecodeError::MissingMsgType)
        );
    }

    #[test]
    fn test_decode_wrong_checksum_is_checksum_mismatch() {
        let body: &[u8] = b"35=0\x0149=A\x0156=B\x01";
        let mut msg = Vec::new();
        msg.extend_from_slice(b"8=FIX.4.4\x01");
        msg.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
        msg.extend_from_slice(body);
        let sum: u64 = msg.iter().map(|&b| u64::from(b)).sum();
        let declared = ((sum % 256) as u8) ^ 0x01;
        msg.extend_from_slice(format!("10={declared:03}\x01").as_bytes());

        assert_eq!(
            Decoder::new(&msg).decode().err(),
            Some(DecodeError::ChecksumMismatch {
                calculated: (sum % 256) as u8,
                declared,
            })
        );
    }

    #[test]
    fn test_decode_out_of_range_checksum_is_typed_error() {
        let body: &[u8] = b"35=0\x0149=A\x01";
        let mut msg = Vec::new();
        msg.extend_from_slice(b"8=FIX.4.4\x01");
        msg.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
        msg.extend_from_slice(body);
        // 999 does not fit in a u8 and must not wrap to 231.
        msg.extend_from_slice(b"10=999\x01");

        assert!(matches!(
            Decoder::new(&msg).decode(),
            Err(DecodeError::InvalidFieldValue { tag: 10, .. })
        ));
    }

    #[test]
    fn test_decode_wrong_checksum_is_accepted_without_validation() {
        // The production path (`with_checksum_validation(false)`, used by the
        // engine after the codec has already verified the frame) ignores the
        // checksum *value* — but the BodyLength cross-check still binds.
        let body: &[u8] = b"35=0\x0149=A\x0156=B\x01";
        let mut msg = Vec::new();
        msg.extend_from_slice(b"8=FIX.4.4\x01");
        msg.extend_from_slice(format!("9={}\x01", body.len()).as_bytes());
        msg.extend_from_slice(body);
        msg.extend_from_slice(b"10=000\x01");

        let Ok(decoded) = Decoder::new(&msg).with_checksum_validation(false).decode() else {
            panic!("a wrong checksum must not stop the validation-off path");
        };
        assert_eq!(*decoded.msg_type(), MsgType::Heartbeat);
        assert_eq!(decoded.body(), Ok(body));

        // Same frame, BodyLength one byte short.
        let mut short = Vec::new();
        short.extend_from_slice(b"8=FIX.4.4\x01");
        short.extend_from_slice(format!("9={}\x01", body.len() - 1).as_bytes());
        short.extend_from_slice(body);
        short.extend_from_slice(b"10=000\x01");
        assert_eq!(
            Decoder::new(&short)
                .with_checksum_validation(false)
                .decode()
                .err(),
            Some(DecodeError::InvalidBodyLength)
        );
    }

    #[test]
    fn test_is_data_tag_matches_the_spec_table() {
        for (length_tag, data_tag) in LENGTH_DATA_PAIRS {
            assert!(is_data_tag(data_tag), "tag {data_tag} is a DATA field");
            assert!(
                !is_data_tag(length_tag),
                "tag {length_tag} is a LENGTH field, not a DATA field"
            );
        }
        let data_tags: Vec<u32> = LENGTH_DATA_PAIRS.iter().map(|(_, data)| *data).collect();
        for tag in candidate_tags() {
            if !data_tags.contains(&tag) {
                assert!(!is_data_tag(tag), "tag {tag} must not be a DATA field");
            }
        }
    }

    #[test]
    fn test_decode_empty_buffer_is_incomplete() {
        assert_eq!(
            Decoder::new(b"").decode().err(),
            Some(DecodeError::Incomplete)
        );
    }

    #[test]
    fn test_reset_clears_pending_data_state() {
        let msg = build_frame(b"35=A\x0195=7\x0196=a\x01b=c\x01d\x01");
        let mut decoder = Decoder::new(&msg);
        assert!(decoder.decode().is_ok());
        decoder.reset();
        assert!(decoder.decode().is_ok());
    }
}
