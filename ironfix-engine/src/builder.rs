/******************************************************************************
   Author: Joaquín Béjar García
   Email: jb@taunais.com
   Date: 27/1/26
******************************************************************************/

//! Engine builder for fluent configuration.
//!
//! [`EngineBuilder`] collects an [`Application`] and session configurations
//! and terminates in a ready-to-run engine: [`EngineBuilder::into_initiator`]
//! for the client side, [`EngineBuilder::into_acceptor`] for one server-side
//! session, and [`EngineBuilder::into_acceptor_registry`] for several
//! server-side sessions on one listener, each inbound Logon routed to its
//! session by CompID.
//!
//! Every setter on this builder configures something an engine actually honors.
//! The builder does **not** carry TLS or reconnection knobs: there is no TLS in
//! the workspace (a caller that needs it hands its own TLS stream to
//! [`Initiator::establish`] or [`Acceptor::serve_stream`]), and reconnection is
//! the consumer's responsibility (the [`Initiator`] establishes a single
//! session per `connect` or `establish`, and a supervisor calls it again). The
//! connect timeout applies to [`Initiator::connect`] only; an acceptor waits
//! for inbound connections and bounds the Logon handshake with
//! [`SessionConfig::logon_timeout`] instead. A [`MessageStore`] set with
//! [`EngineBuilder::with_store`] is attached by every terminal method; since a
//! store belongs to exactly one session, a registry of several sessions takes
//! its stores per session through [`AcceptorRegistry::register`] instead. An
//! outbound throttle set with [`EngineBuilder::with_throttle`] is attached by
//! every terminal method too, to every session: each session gets its own
//! budgets from it.

use crate::acceptor::Acceptor;
use crate::application::{Application, NoOpApplication};
use crate::error::EngineError;
use crate::initiator::Initiator;
use crate::observer::FrameObserver;
use crate::registry::AcceptorRegistry;
use crate::throttle::ThrottleConfig;
use crate::validation::InboundValidation;
use ironfix_session::config::SessionConfig;
use ironfix_store::MessageStore;
use std::sync::Arc;
use std::time::Duration;

/// Builder for configuring a FIX engine.
///
/// Set the [`Application`] and add exactly one [`SessionConfig`], then call
/// [`EngineBuilder::into_initiator`] or [`EngineBuilder::into_acceptor`] to
/// obtain a runnable engine; or add one per counterparty and call
/// [`EngineBuilder::into_acceptor_registry`] to serve them all on one
/// listener.
pub struct EngineBuilder<A: Application = NoOpApplication> {
    /// Application callback handler.
    application: Arc<A>,
    /// Session configurations.
    sessions: Vec<SessionConfig>,
    /// TCP connect timeout applied by [`EngineBuilder::into_initiator`].
    connect_timeout: Duration,
    /// Message store attached by both terminal methods, if any.
    store: Option<Arc<dyn MessageStore>>,
    /// Outbound throttle attached by every terminal method, if any.
    throttle: Option<ThrottleConfig>,
    /// Frame observer attached by every terminal method, if any.
    observer: Option<Arc<dyn FrameObserver>>,
    /// Inbound validation attached by every terminal method, if any.
    validation: Option<InboundValidation>,
}

/// Written by hand rather than derived: `dyn MessageStore` is not `Debug`, and
/// requiring it of every implementation to print one field is the wrong trade.
impl<A: Application> std::fmt::Debug for EngineBuilder<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineBuilder")
            .field("sessions", &self.sessions)
            .field("connect_timeout", &self.connect_timeout)
            .field("store", &self.store.is_some())
            .field("throttle", &self.throttle)
            .field("frame_observer", &self.observer.is_some())
            .field("inbound_validation", &self.validation)
            .finish_non_exhaustive()
    }
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
            store: None,
            throttle: None,
            observer: None,
            validation: None,
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
            store: self.store,
            throttle: self.throttle,
            observer: self.observer,
            validation: self.validation,
        }
    }

    /// Adds a session configuration.
    ///
    /// [`EngineBuilder::into_initiator`] and [`EngineBuilder::into_acceptor`]
    /// build a single-session engine, so exactly one session must be added
    /// before either is called. [`EngineBuilder::into_acceptor_registry`]
    /// takes any number.
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

    /// Attaches a message store to the engine a terminal method produces.
    ///
    /// [`EngineBuilder::into_initiator`] passes it to
    /// [`Initiator::with_store`] and [`EngineBuilder::into_acceptor`] to
    /// [`Acceptor::with_store`]; see those for what a store changes. The store
    /// failure policy and the store timeout are set on the engine itself.
    /// [`EngineBuilder::into_acceptor_registry`] accepts it only for exactly
    /// one session: a store belongs to one session, and with none it would
    /// be silently dropped.
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn MessageStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Attaches an outbound throttle to the engine a terminal method
    /// produces: [`Initiator::with_throttle`] for
    /// [`EngineBuilder::into_initiator`], [`Acceptor::with_throttle`] for
    /// [`EngineBuilder::into_acceptor`], and the same on every [`Acceptor`]
    /// of [`EngineBuilder::into_acceptor_registry`]. Every session gets its
    /// own budgets from it; see [`crate::throttle`] for what it holds back.
    #[must_use]
    pub fn with_throttle(mut self, throttle: ThrottleConfig) -> Self {
        self.throttle = Some(throttle);
        self
    }

    /// Attaches a frame observer to the engine a terminal method produces:
    /// [`Initiator::with_frame_observer`] for
    /// [`EngineBuilder::into_initiator`], [`Acceptor::with_frame_observer`]
    /// for [`EngineBuilder::into_acceptor`], and the same on every
    /// [`Acceptor`] of [`EngineBuilder::into_acceptor_registry`]. See
    /// [`crate::observer`]: it runs inline, must be cheap and must not
    /// panic, and it receives raw bytes, credentials included.
    #[must_use]
    pub fn with_frame_observer(mut self, observer: Arc<dyn FrameObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Attaches inbound dictionary validation to the engine a terminal
    /// method produces: [`Initiator::with_inbound_validation`] for
    /// [`EngineBuilder::into_initiator`], [`Acceptor::with_inbound_validation`]
    /// for [`EngineBuilder::into_acceptor`], and the same on every
    /// [`Acceptor`] of [`EngineBuilder::into_acceptor_registry`]. See
    /// [`crate::validation`] (issue #84, ADR-0031).
    #[must_use]
    pub fn with_inbound_validation(mut self, validation: InboundValidation) -> Self {
        self.validation = Some(validation);
        self
    }

    /// Returns the inbound validation set with `with_inbound_validation`,
    /// if any.
    #[must_use]
    pub const fn inbound_validation(&self) -> Option<&InboundValidation> {
        self.validation.as_ref()
    }

    /// Returns whether a frame observer has been set.
    #[must_use]
    pub const fn has_frame_observer(&self) -> bool {
        self.observer.is_some()
    }

    /// Returns whether a message store has been set.
    #[must_use]
    pub const fn has_store(&self) -> bool {
        self.store.is_some()
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
    /// single configured session, applying the configured connect timeout and
    /// attaching the message store, if one was set.
    ///
    /// # Errors
    /// Returns [`EngineError::Configuration`] unless exactly one session has
    /// been added.
    pub fn into_initiator(self) -> Result<Initiator<A>, EngineError> {
        let config = self.single_session()?;
        let initiator =
            Initiator::new(config, self.application).with_connect_timeout(self.connect_timeout);
        let initiator = match self.throttle {
            Some(throttle) => initiator.with_throttle(throttle),
            None => initiator,
        };
        let initiator = match self.observer {
            Some(observer) => initiator.with_frame_observer(observer),
            None => initiator,
        };
        let initiator = match self.validation {
            Some(validation) => initiator.with_inbound_validation(validation),
            None => initiator,
        };
        Ok(match self.store {
            Some(store) => initiator.with_store(store),
            None => initiator,
        })
    }

    /// Consumes the builder and produces a server-side [`Acceptor`] for the
    /// single configured session, attaching the message store, if one was
    /// set.
    ///
    /// # Errors
    /// Returns [`EngineError::Configuration`] unless exactly one session has
    /// been added.
    pub fn into_acceptor(self) -> Result<Acceptor<A>, EngineError> {
        let config = self.single_session()?;
        let acceptor = Acceptor::new(config, self.application);
        let acceptor = match self.throttle {
            Some(throttle) => acceptor.with_throttle(throttle),
            None => acceptor,
        };
        let acceptor = match self.observer {
            Some(observer) => acceptor.with_frame_observer(observer),
            None => acceptor,
        };
        let acceptor = match self.validation {
            Some(validation) => acceptor.with_inbound_validation(validation),
            None => acceptor,
        };
        Ok(match self.store {
            Some(store) => acceptor.with_store(store),
            None => acceptor,
        })
    }

    /// Consumes the builder and produces an [`AcceptorRegistry`] with one
    /// [`Acceptor`] per configured session, all sharing the application, so
    /// several counterparties can be served on one listener with each inbound
    /// Logon routed to its session by CompID.
    ///
    /// Any number of sessions may be added, none included (sessions can also
    /// be registered later with [`AcceptorRegistry::register`]). A store set
    /// with [`EngineBuilder::with_store`] requires exactly one session, to
    /// which it is attached. For several sessions with stores, or with
    /// per-session settings (failure policy, timeouts, initial sequences),
    /// build each [`Acceptor`] and register it on the registry directly.
    ///
    /// # Errors
    /// [`EngineError::Configuration`] when a store has been set and the number
    /// of sessions is not exactly one: a store belongs to exactly one session
    /// (two sessions writing to one store would interleave their sequence
    /// streams), and with no session it would be dropped without a word.
    /// Otherwise any error [`AcceptorRegistry::register`] returns for a
    /// session: an unusable configuration or version, two sessions whose
    /// identities overlap, or the same session twice.
    pub fn into_acceptor_registry(self) -> Result<AcceptorRegistry<A>, EngineError> {
        if self.store.is_some() && self.sessions.len() != 1 {
            return Err(EngineError::Configuration(format!(
                "a store was set for {} sessions, but a store belongs to exactly one session: \
                 add exactly one session, or attach one store per session with \
                 AcceptorRegistry::register",
                self.sessions.len()
            )));
        }
        let registry = AcceptorRegistry::new();
        for config in self.sessions {
            let acceptor = Acceptor::new(config, Arc::clone(&self.application));
            let acceptor = match &self.throttle {
                Some(throttle) => acceptor.with_throttle(throttle.clone()),
                None => acceptor,
            };
            let acceptor = match &self.observer {
                Some(observer) => acceptor.with_frame_observer(Arc::clone(observer)),
                None => acceptor,
            };
            let acceptor = match &self.validation {
                Some(validation) => acceptor.with_inbound_validation(validation.clone()),
                None => acceptor,
            };
            let acceptor = match &self.store {
                Some(store) => acceptor.with_store(Arc::clone(store)),
                None => acceptor,
            };
            registry.register(acceptor)?;
        }
        Ok(registry)
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
                "{} sessions configured, but a single-session engine requires exactly one \
                 (into_acceptor_registry serves several acceptor sessions)",
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
        assert!(!builder.has_store());
    }

    #[test]
    fn test_engine_builder_store_survives_with_application() {
        let store: Arc<dyn MessageStore> = Arc::new(ironfix_store::MemoryStore::new());
        let builder = EngineBuilder::new()
            .with_store(store)
            .with_application(NoOpApplication);
        assert!(builder.has_store());
        assert!(format!("{builder:?}").contains("store: true"));
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

    fn member_session(member: &str) -> SessionConfig {
        SessionConfig::new(comp_id("VENUE"), comp_id(member), "FIX.4.4")
    }

    #[test]
    fn test_into_acceptor_registry_registers_every_session() {
        let registry = EngineBuilder::new()
            .add_session(member_session("MEMBER_A"))
            .add_session(member_session("MEMBER_B"))
            .into_acceptor_registry();

        match registry {
            Ok(registry) => {
                let mut ids: Vec<String> = registry
                    .session_ids()
                    .iter()
                    .map(ToString::to_string)
                    .collect();
                ids.sort();
                assert_eq!(ids, ["FIX.4.4:VENUE->MEMBER_A", "FIX.4.4:VENUE->MEMBER_B"]);
            }
            Err(err) => panic!("two disjoint sessions must build a registry: {err}"),
        }
    }

    #[test]
    fn test_into_acceptor_registry_without_session_is_empty() {
        match EngineBuilder::new().into_acceptor_registry() {
            Ok(registry) => assert!(registry.session_ids().is_empty()),
            Err(err) => panic!("an empty registry must build: {err}"),
        }
    }

    #[test]
    fn test_into_acceptor_registry_refuses_one_store_for_several_sessions() {
        let store: Arc<dyn MessageStore> = Arc::new(ironfix_store::MemoryStore::new());
        match EngineBuilder::new()
            .add_session(member_session("MEMBER_A"))
            .add_session(member_session("MEMBER_B"))
            .with_store(store)
            .into_acceptor_registry()
        {
            Err(EngineError::Configuration(detail)) => {
                assert!(detail.contains("exactly one session"), "got {detail}");
            }
            other => panic!("one store for two sessions must be refused: {other:?}"),
        }
    }

    #[test]
    fn test_into_acceptor_registry_refuses_a_store_without_a_session() {
        let store: Arc<dyn MessageStore> = Arc::new(ironfix_store::MemoryStore::new());
        match EngineBuilder::new()
            .with_store(store)
            .into_acceptor_registry()
        {
            Err(EngineError::Configuration(detail)) => {
                assert!(detail.contains("0 sessions"), "got {detail}");
            }
            other => panic!("a store with no session must be refused: {other:?}"),
        }
    }

    #[test]
    fn test_into_acceptor_registry_accepts_a_store_for_one_session() {
        let store: Arc<dyn MessageStore> = Arc::new(ironfix_store::MemoryStore::new());
        let registry = EngineBuilder::new()
            .add_session(member_session("MEMBER_A"))
            .with_store(store)
            .into_acceptor_registry();
        match registry {
            Ok(registry) => assert_eq!(registry.session_ids().len(), 1),
            Err(err) => panic!("one store for one session must build: {err}"),
        }
    }

    #[test]
    fn test_into_acceptor_registry_refuses_overlapping_sessions() {
        match EngineBuilder::new()
            .add_session(member_session("MEMBER_A"))
            .add_session(member_session("MEMBER_A"))
            .into_acceptor_registry()
        {
            Err(EngineError::Configuration(detail)) => {
                assert!(detail.contains("overlaps"), "got {detail}");
            }
            other => panic!("the same session twice must be refused: {other:?}"),
        }
    }

    /// A one-budget throttle for the builder tests.
    fn throttle() -> ThrottleConfig {
        use crate::throttle::ThrottleBudget;
        match ThrottleConfig::builder(ThrottleBudget::new(10, Duration::from_secs(1))).build() {
            Ok(throttle) => throttle,
            Err(err) => panic!("the test throttle must build: {err}"),
        }
    }

    #[test]
    fn test_engine_builder_throttle_reaches_every_terminal_method() {
        // Set before the application, so it survives `with_application`.
        let builder = || {
            EngineBuilder::new()
                .with_throttle(throttle())
                .with_application(NoOpApplication)
                .add_session(session())
        };
        assert!(format!("{:?}", builder()).contains("ThrottleConfig"));

        match builder().into_initiator() {
            Ok(initiator) => assert!(initiator.throttle().is_some()),
            Err(err) => panic!("one session builds an initiator: {err}"),
        }
        match builder().into_acceptor() {
            Ok(acceptor) => assert!(acceptor.throttle().is_some()),
            Err(err) => panic!("one session builds an acceptor: {err}"),
        }
        match builder().into_acceptor_registry() {
            Ok(registry) => assert_eq!(registry.session_ids().len(), 1),
            Err(err) => panic!("one session builds a registry: {err}"),
        }
    }

    #[test]
    fn test_engine_builder_frame_observer_reaches_every_terminal_method() {
        struct Quiet;
        impl FrameObserver for Quiet {
            fn on_inbound(&self, _: &[u8], _: &crate::observer::Observation<'_>) {}
            fn on_outbound(&self, _: &[u8], _: &crate::observer::Observation<'_>) {}
        }
        let observer: Arc<dyn FrameObserver> = Arc::new(Quiet);
        let builder = || {
            EngineBuilder::new()
                .add_session(session())
                .with_frame_observer(Arc::clone(&observer))
        };
        assert!(builder().has_frame_observer());
        match builder().into_initiator() {
            Ok(initiator) => assert!(initiator.has_frame_observer()),
            Err(err) => panic!("one session must build an initiator: {err}"),
        }
        match builder().into_acceptor() {
            Ok(acceptor) => assert!(acceptor.has_frame_observer()),
            Err(err) => panic!("one session must build an acceptor: {err}"),
        }
        match EngineBuilder::new().add_session(session()).into_initiator() {
            Ok(initiator) => assert!(!initiator.has_frame_observer()),
            Err(err) => panic!("one session must build an initiator: {err}"),
        }
    }

    #[test]
    fn test_engine_builder_inbound_validation_reaches_every_terminal_method() {
        use crate::validation::{InboundValidation, ValidationPolicy};
        use ironfix_core::message::RawMessage;
        use ironfix_core::{InboundRejection, InboundValidator};
        struct Pass;
        impl InboundValidator for Pass {
            fn validate(&self, _: &RawMessage<'_>) -> Result<(), InboundRejection> {
                Ok(())
            }
        }
        let validation = InboundValidation::new(Arc::new(Pass), ValidationPolicy::Reject);
        let builder = || {
            EngineBuilder::new()
                .add_session(session())
                .with_inbound_validation(validation.clone())
        };
        assert!(builder().inbound_validation().is_some());
        match builder().into_initiator() {
            Ok(initiator) => assert_eq!(
                initiator
                    .inbound_validation()
                    .map(InboundValidation::policy),
                Some(ValidationPolicy::Reject)
            ),
            Err(err) => panic!("into_initiator failed: {err}"),
        }
        match builder().into_acceptor() {
            Ok(acceptor) => assert!(acceptor.inbound_validation().is_some()),
            Err(err) => panic!("into_acceptor failed: {err}"),
        }
        match builder().into_acceptor_registry() {
            Ok(_) => {}
            Err(err) => panic!("into_acceptor_registry failed: {err}"),
        }
        match EngineBuilder::new().add_session(session()).into_initiator() {
            Ok(initiator) => assert!(initiator.inbound_validation().is_none()),
            Err(err) => panic!("into_initiator failed: {err}"),
        }
    }

    #[test]
    fn test_engine_builder_without_throttle_attaches_none() {
        match EngineBuilder::new().add_session(session()).into_initiator() {
            Ok(initiator) => assert!(initiator.throttle().is_none()),
            Err(err) => panic!("one session builds an initiator: {err}"),
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
