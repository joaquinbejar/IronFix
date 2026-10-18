/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 17/10/26
******************************************************************************/

//! Transport plus application dictionary composition for FIXT.1.1 sessions.
//!
//! A FIXT.1.1 session separates the transport from the application: the
//! session-level header, trailer and admin messages are FIXT.1.1, and the
//! application messages are any application version FIXT.1.1 can carry (FIX
//! 4.0 through 4.4, ApplVerID `2` to `6`, as well as FIX 5.0, 5.0 SP1 and 5.0
//! SP2, ApplVerID `7` to `9`). QuickFIX ships this as two dictionaries: a
//! *transport* dictionary (`FIXT11.xml`: the standard header and trailer plus
//! the admin messages) and an *application* dictionary (for example
//! `FIX50SP2.xml`: the application messages, with an empty header and
//! trailer). [`SessionDictionary`] pairs them, and
//! [`Validator::for_session`](crate::Validator::for_session) validates a
//! message against the pair with QuickFIX-like semantics:
//!
//! - a message type the transport dictionary defines as `admin` is
//!   validated entirely against the transport dictionary;
//! - any other message type is looked up in the application dictionary; its
//!   header and trailer tags resolve against the transport dictionary and its
//!   body tags against the application dictionary.
//!
//! See the [`validator`](crate::validator) module docs for where this departs
//! from QuickFIX. In particular the composition does **not** read or enforce
//! `ApplVerID(1128)` or `DefaultApplVerID(1137)`: choosing which application
//! dictionary answers a given message is the caller's decision, made when the
//! pair is built.
//!
//! # Upstream deviation in the embedded FIXT 1.1 dictionary
//!
//! FIXT 1.1 defines the Logon `MsgTypeGrp` component as the `NoMsgTypes(384)`
//! repeating group (`RefMsgType(372)`, `MsgDirection(385)`,
//! `RefApplVerID(1130)`, `RefApplExtID(1406)`, `RefCstmApplVerID(1131)`,
//! `DefaultVerIndicator(1410)`). The QuickFIX `FIXT11.xml` vendored as
//! [`Dictionary::fixt11`] defines `MsgTypeGrp` with no members and does not
//! define tags 384 and 385 at all, so a Logon carrying the group is reported
//! as invalid. The file stays unpatched. To accept the group, load a FIXT 1.1
//! dictionary that defines it with
//! [`Dictionary::from_quickfix_xml`] and compose that instead.

use crate::loader::DictionaryError;
use crate::schema::{Dictionary, Version};

/// A FIXT.1.1 transport dictionary composed with an application dictionary.
///
/// The application dictionary may be any version FIXT.1.1 carries: FIX 4.0
/// through 4.4, or FIX 5.0 through 5.0 SP2. Both dictionaries are borrowed;
/// nothing is copied or merged, so the pair is as cheap to build and to copy
/// as two references. Validate messages against it with
/// [`Validator::for_session`](crate::Validator::for_session).
///
/// The embedded FIXT 1.1 transport ([`Dictionary::fixt11`]) does not define
/// the Logon `NoMsgTypes(384)` group, an upstream QuickFIX deviation described
/// in the [module docs](crate::composition).
///
/// # Examples
///
/// ```
/// use ironfix_dictionary::{Dictionary, SessionDictionary, Validator};
///
/// let session = SessionDictionary::new(Dictionary::fixt11()?, Dictionary::fix50sp2()?)?;
/// assert_eq!(session.transport().version.begin_string(), "FIXT.1.1");
/// assert_eq!(session.application().version.appl_ver_id(), Some("9"));
/// let _validator = Validator::for_session(&session);
/// # Ok::<(), ironfix_dictionary::DictionaryError>(())
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SessionDictionary<'d> {
    /// Answers the standard header and trailer and the admin messages.
    transport: &'d Dictionary,
    /// Answers application message bodies.
    application: &'d Dictionary,
}

impl<'d> SessionDictionary<'d> {
    /// Composes a transport dictionary with an application dictionary.
    ///
    /// # Arguments
    /// * `transport` - A FIXT.1.1 dictionary ([`Version::Fixt11`])
    /// * `application` - An application dictionary of any version FIXT.1.1
    ///   carries: FIX 4.0, 4.1, 4.2, 4.3, 4.4, 5.0, 5.0 SP1 or 5.0 SP2
    ///
    /// # Errors
    /// Returns [`DictionaryError::IncompatibleComposition`] when `transport`
    /// is not a FIXT.1.1 dictionary, or when `application` is a FIXT.1.1
    /// dictionary (a transport cannot also be the application).
    pub const fn new(
        transport: &'d Dictionary,
        application: &'d Dictionary,
    ) -> Result<Self, DictionaryError> {
        let transport_ok = matches!(transport.version, Version::Fixt11);
        // FIXT.1.1 carries every FIX application version, 4.0 through 5.0
        // SP2 (ApplVerID 2 to 9). The match is spelled out, rather than
        // derived from `Version::appl_ver_id`, because that helper answers a
        // different question (what to stamp in 1128/1137 for a session
        // configured with that version) and has no value for FIX 4.x. Being
        // exhaustive, it forces a decision here when a version is added.
        let application_ok = match application.version {
            Version::Fix40
            | Version::Fix41
            | Version::Fix42
            | Version::Fix43
            | Version::Fix44
            | Version::Fix50
            | Version::Fix50Sp1
            | Version::Fix50Sp2 => true,
            Version::Fixt11 => false,
        };
        if transport_ok && application_ok {
            Ok(Self {
                transport,
                application,
            })
        } else {
            Err(DictionaryError::IncompatibleComposition {
                transport: transport.version,
                application: application.version,
            })
        }
    }

    /// Returns the transport (FIXT.1.1) dictionary.
    #[must_use]
    pub const fn transport(&self) -> &'d Dictionary {
        self.transport
    }

    /// Returns the application dictionary.
    #[must_use]
    pub const fn application(&self) -> &'d Dictionary {
        self.application
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    /// Unwraps a `Result` with test context instead of `.unwrap()`.
    #[track_caller]
    fn ok<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err:?}"),
        }
    }

    /// Returns the error a composition is expected to fail with.
    #[track_caller]
    fn compose_err(transport: &Dictionary, application: &Dictionary) -> DictionaryError {
        match SessionDictionary::new(transport, application) {
            Ok(_) => panic!("expected the composition to be rejected, but it was built"),
            Err(err) => err,
        }
    }

    #[test]
    fn test_session_dictionary_new_fixt11_with_fix50sp2_composes() {
        let transport = ok(Dictionary::fixt11(), "FIXT 1.1 loads");
        let application = ok(Dictionary::fix50sp2(), "FIX 5.0 SP2 loads");
        let session = ok(
            SessionDictionary::new(transport, application),
            "FIXT 1.1 + FIX 5.0 SP2 compose",
        );
        assert!(std::ptr::eq(session.transport(), transport));
        assert!(std::ptr::eq(session.application(), application));
    }

    #[test]
    fn test_session_dictionary_new_fixt11_with_fix4x_composes() {
        // FIXT.1.1 carries FIX 4.x application messages (ApplVerID 2 to 6).
        let transport = ok(Dictionary::fixt11(), "FIXT 1.1 loads");
        for application in [
            ok(Dictionary::fix42(), "FIX 4.2 loads"),
            ok(Dictionary::fix44(), "FIX 4.4 loads"),
        ] {
            let session = ok(
                SessionDictionary::new(transport, application),
                "FIXT 1.1 + FIX 4.x compose",
            );
            assert!(std::ptr::eq(session.application(), application));
        }
    }

    #[test]
    fn test_session_dictionary_new_non_fixt_transport_is_rejected() {
        let fix44 = ok(Dictionary::fix44(), "FIX 4.4 loads");
        let fix50sp2 = ok(Dictionary::fix50sp2(), "FIX 5.0 SP2 loads");
        assert_eq!(
            compose_err(fix44, fix50sp2),
            DictionaryError::IncompatibleComposition {
                transport: Version::Fix44,
                application: Version::Fix50Sp2,
            }
        );
    }

    #[test]
    fn test_session_dictionary_new_fixt11_as_application_is_rejected() {
        let fixt11 = ok(Dictionary::fixt11(), "FIXT 1.1 loads");
        assert_eq!(
            compose_err(fixt11, fixt11),
            DictionaryError::IncompatibleComposition {
                transport: Version::Fixt11,
                application: Version::Fixt11,
            }
        );
    }

    #[test]
    fn test_session_dictionary_new_swapped_roles_are_rejected() {
        let fixt11 = ok(Dictionary::fixt11(), "FIXT 1.1 loads");
        let fix50sp2 = ok(Dictionary::fix50sp2(), "FIX 5.0 SP2 loads");
        assert_eq!(
            compose_err(fix50sp2, fixt11),
            DictionaryError::IncompatibleComposition {
                transport: Version::Fix50Sp2,
                application: Version::Fixt11,
            }
        );
    }

    #[test]
    fn test_session_dictionary_new_accepts_every_application_version_but_fixt11() {
        // Only some versions are embedded, but a caller-supplied dictionary
        // of any application version composes the same way.
        let fixt11 = ok(Dictionary::fixt11(), "FIXT 1.1 loads");
        for version in Version::ALL {
            let application = Dictionary::new(version);
            let composed = SessionDictionary::new(fixt11, &application);
            assert_eq!(
                composed.is_ok(),
                version != Version::Fixt11,
                "{version} composition outcome"
            );
        }
    }

    #[test]
    fn test_session_dictionary_new_rejects_every_non_fixt_transport() {
        let fix50sp2 = ok(Dictionary::fix50sp2(), "FIX 5.0 SP2 loads");
        for version in Version::ALL {
            let transport = Dictionary::new(version);
            let composed = SessionDictionary::new(&transport, fix50sp2);
            assert_eq!(
                composed.is_ok(),
                version == Version::Fixt11,
                "{version} as transport"
            );
        }
    }
}
