/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Engine builder for fluent configuration.
//!
//! [`EngineBuilder`] collects an [`Application`] and a session configuration
//! and terminates in a ready-to-run engine: [`EngineBuilder::into_initiator`]
//! for the client side, [`EngineBuilder::into_acceptor`] for the server side.
//!
//! Every setter on this builder configures something an engine actually honors.
//! The builder does **not** carry TLS or reconnection knobs: there is no TLS in
//! the workspace, and reconnection is the consumer's responsibility (the
//! [`Initiator`] establishes a single session per `connect`, and a supervisor
//! calls it again). The connect timeout applies to the initiator only; an
//! acceptor waits for inbound connections and bounds the Logon handshake with
//! [`SessionConfig::logon_timeout`] instead.

use crate::acceptor::Acceptor;
use crate::application::{Application, NoOpApplication};
use crate::error::EngineError;
use crate::initiator::Initiator;
use ironfix_session::config::SessionConfig;
use std::sync::Arc;
use std::time::Duration;

/// Builder for configuring a FIX engine.
///
/// Set the [`Application`] and add exactly one [`SessionConfig`], then call
/// [`EngineBuilder::into_initiator`] or [`EngineBuilder::into_acceptor`] to
/// obtain a runnable engine.
#[derive(Debug)]
pub struct EngineBuilder<A: Application = NoOpApplication> {
    /// Application callback handler.
    application: Arc<A>,
    /// Session configurations.
    sessions: Vec<SessionConfig>,
    /// TCP connect timeout applied by [`EngineBuilder::into_initiator`].
    connect_timeout: Duration,
}

impl Default for EngineBuilder<NoOpApplication> {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineBuilder<NoOpApplication> {
    /// Creates a new engine builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            application: Arc::new(NoOpApplication),
            sessions: Vec::new(),
            connect_timeout: Duration::from_secs(30),
        }
    }
}

impl<A: Application + 'static> EngineBuilder<A> {
    /// Sets the application callback handler.
    #[must_use]
    pub fn with_application<B: Application>(self, application: B) -> EngineBuilder<B> {
        EngineBuilder {
            application: Arc::new(application),
            sessions: self.sessions,
            connect_timeout: self.connect_timeout,
        }
    }

    /// Adds a session configuration.
    ///
    /// The terminal methods build a single-session engine, so exactly one
    /// session must be added before [`EngineBuilder::into_initiator`] or
    /// [`EngineBuilder::into_acceptor`] is called.
    #[must_use]
    pub fn add_session(mut self, config: SessionConfig) -> Self {
        self.sessions.push(config);
        self
    }

    /// Sets the TCP connect timeout used by [`EngineBuilder::into_initiator`]
    /// (default 30s). It has no effect on an acceptor.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Returns the configured sessions.
    #[must_use]
    pub fn sessions(&self) -> &[SessionConfig] {
        &self.sessions
    }

    /// Returns the connection timeout.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Returns the application handler.
    #[must_use]
    pub fn application(&self) -> Arc<A> {
        Arc::clone(&self.application)
    }

    /// Consumes the builder and produces a client-side [`Initiator`] for the
    /// single configured session, applying the configured connect timeout.
    ///
    /// # Errors
    /// Returns [`EngineError::Configuration`] unless exactly one session has
    /// been added.
    pub fn into_initiator(self) -> Result<Initiator<A>, EngineError> {
        let config = self.single_session()?;
        Ok(Initiator::new(config, self.application).with_connect_timeout(self.connect_timeout))
    }

    /// Consumes the builder and produces a server-side [`Acceptor`] for the
    /// single configured session.
    ///
    /// # Errors
    /// Returns [`EngineError::Configuration`] unless exactly one session has
    /// been added.
    pub fn into_acceptor(self) -> Result<Acceptor<A>, EngineError> {
        let config = self.single_session()?;
        Ok(Acceptor::new(config, self.application))
    }

    /// Extracts the single configured session, or explains why there is not
    /// exactly one.
    fn single_session(&self) -> Result<SessionConfig, EngineError> {
        match self.sessions.as_slice() {
            [config] => Ok(config.clone()),
            [] => Err(EngineError::Configuration(
                "no session configured: add exactly one with add_session".to_string(),
            )),
            many => Err(EngineError::Configuration(format!(
                "{} sessions configured, but a single-session engine requires exactly one",
                many.len()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironfix_core::types::CompId;

    /// Fails the test with context instead of `.unwrap()` / `.expect()`.
    #[track_caller]
    fn comp_id(value: &str) -> CompId {
        match CompId::new(value) {
            Ok(id) => id,
            Err(err) => panic!("test CompId must be valid: {err}"),
        }
    }

    fn session() -> SessionConfig {
        SessionConfig::new(comp_id("SENDER"), comp_id("TARGET"), "FIX.4.4")
    }

    #[test]
    fn test_engine_builder_default_is_empty() {
        let builder = EngineBuilder::new();
        assert_eq!(builder.connect_timeout(), Duration::from_secs(30));
        assert!(builder.sessions().is_empty());
    }

    #[test]
    fn test_engine_builder_add_session_records_it() {
        let builder = EngineBuilder::new()
            .add_session(session())
            .with_connect_timeout(Duration::from_secs(60));

        assert_eq!(builder.sessions().len(), 1);
        assert_eq!(builder.connect_timeout(), Duration::from_secs(60));
    }

    #[test]
    fn test_into_initiator_single_session_carries_connect_timeout() {
        let initiator = EngineBuilder::new()
            .add_session(session())
            .with_connect_timeout(Duration::from_secs(7))
            .into_initiator();

        match initiator {
            Ok(initiator) => {
                assert_eq!(initiator.session_id().to_string(), "FIX.4.4:SENDER->TARGET");
            }
            Err(err) => panic!("a single-session builder must produce an initiator: {err}"),
        }
    }

    #[test]
    fn test_into_acceptor_single_session_builds() {
        let acceptor = EngineBuilder::new().add_session(session()).into_acceptor();

        match acceptor {
            Ok(acceptor) => {
                assert_eq!(acceptor.session_id().to_string(), "FIX.4.4:SENDER->TARGET");
            }
            Err(err) => panic!("a single-session builder must produce an acceptor: {err}"),
        }
    }

    #[test]
    fn test_into_initiator_without_session_is_configuration_error() {
        match EngineBuilder::new().into_initiator() {
            Err(EngineError::Configuration(detail)) => assert!(detail.contains("no session")),
            other => panic!("an empty builder must fail with Configuration, got {other:?}"),
        }
    }

    #[test]
    fn test_into_acceptor_with_two_sessions_is_configuration_error() {
        match EngineBuilder::new()
            .add_session(session())
            .add_session(session())
            .into_acceptor()
        {
            Err(EngineError::Configuration(detail)) => assert!(detail.contains("2 sessions")),
            other => panic!("a two-session builder must fail with Configuration, got {other:?}"),
        }
    }
}
