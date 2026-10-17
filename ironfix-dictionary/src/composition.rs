/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 17/10/26
******************************************************************************/

//! Transport plus application dictionary composition for FIXT.1.1 sessions.
//!
//! FIX 5.0 and later run over a FIXT.1.1 session, and QuickFIX ships them as
//! two dictionaries: a *transport* dictionary (`FIXT11.xml`: the standard
//! header and trailer plus the session-level admin messages) and an
//! *application* dictionary (`FIX50SP2.xml`: the application messages, with an
//! empty header and trailer). Neither describes a complete message on its
//! own. [`SessionDictionary`] pairs them, and
//! [`Validator::for_session`](crate::Validator::for_session) validates a
//! message against the pair with QuickFIX's semantics:
//!
//! - a message type the transport dictionary defines as `admin` is
//!   validated entirely against the transport dictionary;
//! - any other message type is looked up in the application dictionary; its
//!   header and trailer tags resolve against the transport dictionary and its
//!   body tags against the application dictionary.
//!
//! The composition does **not** read or enforce `ApplVerID(1128)` or
//! `DefaultApplVerID(1137)`: choosing which application dictionary answers a
//! given message is the caller's decision, made when the pair is built.

use crate::loader::DictionaryError;
use crate::schema::{Dictionary, Version};

/// A FIXT.1.1 transport dictionary composed with a FIX 5.0 or later
/// application dictionary.
///
/// Both dictionaries are borrowed; nothing is copied or merged, so the pair
/// is as cheap to build and to copy as two references. Validate messages
/// against it with [`Validator::for_session`](crate::Validator::for_session).
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
    /// * `application` - A FIX 5.0, 5.0 SP1, or 5.0 SP2 dictionary: a version
    ///   that carries an `ApplVerID`
    ///
    /// # Errors
    /// Returns [`DictionaryError::IncompatibleComposition`] when `transport`
    /// is not a FIXT.1.1 dictionary, or when `application` is not a FIX 5.0
    /// family dictionary (a FIX 4.x dictionary, or a second FIXT.1.1 one).
    pub const fn new(
        transport: &'d Dictionary,
        application: &'d Dictionary,
    ) -> Result<Self, DictionaryError> {
        let transport_ok = matches!(transport.version, Version::Fixt11);
        // An application version over FIXT.1.1 is exactly a version that has
        // an ApplVerID; FIXT.1.1 itself and FIX 4.x have none.
        let application_ok = application.version.appl_ver_id().is_some();
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

    /// Returns the application (FIX 5.0 family) dictionary.
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
    fn test_session_dictionary_new_fix44_as_transport_is_rejected() {
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
    fn test_session_dictionary_new_fix4x_as_application_is_rejected() {
        let fixt11 = ok(Dictionary::fixt11(), "FIXT 1.1 loads");
        for application in [
            ok(Dictionary::fix42(), "FIX 4.2 loads"),
            ok(Dictionary::fix44(), "FIX 4.4 loads"),
        ] {
            assert_eq!(
                compose_err(fixt11, application),
                DictionaryError::IncompatibleComposition {
                    transport: Version::Fixt11,
                    application: application.version,
                }
            );
        }
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
    fn test_session_dictionary_new_every_fix50_family_version_is_accepted() {
        // Only FIX 5.0 SP2 is embedded, but a caller-supplied FIX 5.0 or
        // 5.0 SP1 dictionary composes the same way: the predicate is the
        // version's ApplVerID, not a list of embedded files.
        let fixt11 = ok(Dictionary::fixt11(), "FIXT 1.1 loads");
        for version in Version::ALL {
            let application = Dictionary::new(version);
            let composed = SessionDictionary::new(fixt11, &application);
            assert_eq!(
                composed.is_ok(),
                version.appl_ver_id().is_some(),
                "{version} composition outcome"
            );
        }
    }
}
