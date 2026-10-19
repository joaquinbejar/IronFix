/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 20/10/26
******************************************************************************/

//! Inbound application-message validation on the session path (issue #84,
//! ADR-0031).
//!
//! An [`InboundValidation`] pairs an
//! [`InboundValidator`], typically an
//! `ironfix_dictionary::Validator`, `Dictionary` or `SessionDictionary`, with
//! a [`ValidationPolicy`]. Attach it with
//! [`Initiator::with_inbound_validation`](crate::Initiator::with_inbound_validation),
//! [`Acceptor::with_inbound_validation`](crate::Acceptor::with_inbound_validation)
//! or [`EngineBuilder::with_inbound_validation`](crate::EngineBuilder::with_inbound_validation).
//! The engine names only the trait from `ironfix-core`, so it does not depend
//! on `ironfix-dictionary`.
//!
//! # Where the check runs
//!
//! On every **application** message that is next in sequence, after
//! everything that decides whether the message is the session's to act on,
//! and immediately before it is handed to the dispatcher for `from_app`:
//!
//! 1. framing and decoding (a malformed body is rejected by the #102 path
//!    and never reaches the validator);
//! 2. `MsgSeqNum` presence, identity (49/56), `SendingTime` (52);
//! 3. the sequence check: a message above the expectation is not validated
//!    when it arrives; under `GapPolicy::Queue` it is validated when it is
//!    released in order, and otherwise when its resend arrives. A duplicate
//!    below the expectation is dropped unvalidated;
//! 4. on FIXT.1.1, the `ApplVerID` (1128) check (#67): a message in a
//!    version the session refuses is rejected for that, not validated
//!    against a dictionary of another version;
//! 5. **this validation**;
//! 6. the dispatcher and `from_app`.
//!
//! Administrative messages are never validated here: the session layer
//! already checks every field it acts on.
//!
//! # Policies
//!
//! - [`ValidationPolicy::Off`] (the default): the validator is not called;
//!   one branch per application message.
//! - [`ValidationPolicy::Log`]: a failure logs a warning (session, number,
//!   MsgType, defect, `RefTagID`, never a field value) and the message is
//!   delivered as usual.
//! - [`ValidationPolicy::Reject`]: a failure is answered with a Reject and
//!   the message never reaches `from_app`. Its `MsgSeqNum` is consumed, as
//!   for any message answered with a session-level Reject: `MsgSeqNum + 1`
//!   is persisted as the next target before the expectation moves, and the
//!   session stays up.
//!
//! # The Reject
//!
//! By default a session-level Reject (35=3): `RefSeqNum` (45), `RefTagID`
//! (371), `RefMsgType` (372), `SessionRejectReason` (373) and `Text` (58).
//! The 373 code depends on the session's version: FIX 4.3 and later carry
//! the code of the [`InboundDefect`](ironfix_core::InboundDefect); FIX 4.2
//! defines codes 0 to 11 only, so a defect whose code is 13, 15, 16 or 99
//! goes out without 373 (371 and 58 still name it); FIX 4.0 and 4.1 Rejects
//! carry 45 and 58 only, as for every Reject the engine sends.
//!
//! With [`ValidationRejectMessage::BusinessMessageReject`], the two defects
//! that are about the application's content, a missing required tag and an
//! unsupported message type, are answered with a BusinessMessageReject
//! (35=j) instead: `RefSeqNum` (45), `RefMsgType` (372),
//! `BusinessRejectReason` (380) = 5 (*Conditionally required field missing*)
//! or 3 (*Unsupported message type*), and `Text` (58), which names the tag.
//! Every other defect is a syntax problem of the message and still gets a
//! session-level Reject. FIX 4.0 and 4.1 define no BusinessMessageReject, so
//! there the option has no effect. A BusinessMessageReject is an application
//! message: it spends an outbound number, goes through `to_app_checked` and
//! is filed for resend like any other.
//!
//! The `Text` (58) of either Reject is the validator's value-free text: it
//! never quotes a field's bytes, so `Password` (554), `NewPassword` (925)
//! and `RawData` (96) cannot leak through it.
//!
//! # Cost
//!
//! With `Off`, or with no validation attached, nothing is allocated and the
//! validator is never called. With `Log` or `Reject` the cost is the
//! validator's: `ironfix_dictionary::Validator::validate` allocates per
//! message (its scope expansion and its error list).

use ironfix_core::InboundValidator;
use std::fmt;
use std::sync::Arc;

/// What the session does with an inbound application message that fails
/// validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ValidationPolicy {
    /// Do not validate. The default.
    #[default]
    Off,
    /// Validate, log a value-free warning on failure, and deliver the
    /// message anyway.
    Log,
    /// Validate, and answer a failure with a Reject: the message's number is
    /// consumed and it never reaches `from_app`.
    Reject,
}

/// Which message a [`ValidationPolicy::Reject`] answers a content defect
/// with (see the [module docs](crate::validation)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ValidationRejectMessage {
    /// A session-level Reject (35=3) for every defect. The default.
    #[default]
    SessionReject,
    /// A BusinessMessageReject (35=j) for a missing required tag or an
    /// unsupported message type, on FIX 4.2 and later; a session-level
    /// Reject for every other defect.
    BusinessMessageReject,
}

/// A validator and the policy that decides what its verdict does.
#[derive(Clone)]
pub struct InboundValidation {
    validator: Arc<dyn InboundValidator>,
    policy: ValidationPolicy,
    reject_message: ValidationRejectMessage,
}

/// Written by hand: `dyn InboundValidator` is not `Debug`.
impl fmt::Debug for InboundValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundValidation")
            .field("policy", &self.policy)
            .field("reject_message", &self.reject_message)
            .finish_non_exhaustive()
    }
}

impl InboundValidation {
    /// Creates a validation step with session-level Rejects.
    ///
    /// # Arguments
    /// * `validator` - What checks each inbound application message, for
    ///   example an `Arc<ironfix_dictionary::Dictionary>` or a
    ///   `Validator<'static>` over an embedded dictionary
    /// * `policy` - What a failure does
    #[must_use]
    pub fn new(validator: Arc<dyn InboundValidator>, policy: ValidationPolicy) -> Self {
        Self {
            validator,
            policy,
            reject_message: ValidationRejectMessage::SessionReject,
        }
    }

    /// Chooses the message [`ValidationPolicy::Reject`] answers content
    /// defects with.
    #[must_use]
    pub const fn with_reject_message(mut self, reject_message: ValidationRejectMessage) -> Self {
        self.reject_message = reject_message;
        self
    }

    /// The policy.
    #[must_use]
    pub const fn policy(&self) -> ValidationPolicy {
        self.policy
    }

    /// The message a content defect is answered with under
    /// [`ValidationPolicy::Reject`].
    #[must_use]
    pub const fn reject_message(&self) -> ValidationRejectMessage {
        self.reject_message
    }

    /// The validator.
    #[must_use]
    pub fn validator(&self) -> &Arc<dyn InboundValidator> {
        &self.validator
    }

    /// `self` when it validates anything, `None` under
    /// [`ValidationPolicy::Off`]: what a session's reactor holds, so `Off`
    /// costs one branch and never calls the validator.
    #[must_use]
    pub(crate) fn active(this: Option<Self>) -> Option<Self> {
        this.filter(|validation| validation.policy != ValidationPolicy::Off)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironfix_core::message::RawMessage;
    use ironfix_core::{InboundDefect, InboundRejection};

    struct Never;
    impl InboundValidator for Never {
        fn validate(&self, _msg: &RawMessage<'_>) -> Result<(), InboundRejection> {
            Err(InboundRejection::new(InboundDefect::Other, None, "no"))
        }
    }

    #[test]
    fn test_validation_policy_defaults_to_off() {
        assert_eq!(ValidationPolicy::default(), ValidationPolicy::Off);
        assert_eq!(
            ValidationRejectMessage::default(),
            ValidationRejectMessage::SessionReject
        );
    }

    #[test]
    fn test_inbound_validation_off_is_not_active() {
        let off = InboundValidation::new(Arc::new(Never), ValidationPolicy::Off);
        assert!(InboundValidation::active(Some(off)).is_none());
        assert!(InboundValidation::active(None).is_none());
        for policy in [ValidationPolicy::Log, ValidationPolicy::Reject] {
            let on = InboundValidation::new(Arc::new(Never), policy);
            let active = InboundValidation::active(Some(on));
            assert_eq!(active.map(|v| v.policy()), Some(policy));
        }
    }

    #[test]
    fn test_inbound_validation_with_reject_message_sets_it() {
        let validation = InboundValidation::new(Arc::new(Never), ValidationPolicy::Reject)
            .with_reject_message(ValidationRejectMessage::BusinessMessageReject);
        assert_eq!(
            validation.reject_message(),
            ValidationRejectMessage::BusinessMessageReject
        );
        assert_eq!(validation.policy(), ValidationPolicy::Reject);
        let shown = format!("{validation:?}");
        assert!(shown.contains("Reject"));
    }
}
