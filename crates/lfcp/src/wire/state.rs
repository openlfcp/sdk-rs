//! Connection, session and per-Resource sync state machines (LFCP-WIRE-01
//! §63–§65), as pure transition functions. Driving them with I/O, timers
//! and messages is the client's and server's job.
//!
//! Only the transitions the §63–§65 diagrams draw are allowed; any other
//! event is [`Error::IllegalTransition`], a local error with no wire code.
//!
//! | Machine | From | Event | To | § |
//! | --- | --- | --- | --- | --- |
//! | client connection | DISCONNECTED | open WebSocket | CONNECTING | §63 |
//! | | CONNECTING | WebSocket + `lfcp-1` accepted | NEGOTIATING | §63, §30 |
//! | | CONNECTING | connection failed or `lfcp-1` not accepted | DISCONNECTED | §63 |
//! | | NEGOTIATING | HELLO / CHALLENGE | AUTHENTICATING | §63 |
//! | | AUTHENTICATING | AUTH / READY | READY | §63 |
//! | | READY | open/close resources | READY | §63 |
//! | | READY | socket closed | DISCONNECTED | §63 |
//! | | NEGOTIATING | fatal error | DISCONNECTED | §63 |
//! | | AUTHENTICATING | auth failure | DISCONNECTED | §63 |
//! | server session | ACCEPTED | (start) | WAIT_HELLO | §64 |
//! | | WAIT_HELLO | valid HELLO, send CHALLENGE | WAIT_AUTH | §64 |
//! | | WAIT_AUTH | valid AUTH, send READY | READY | §64 |
//! | | READY | LFCP messages | READY | §64 |
//! | | WAIT_HELLO | protocol violation | CLOSED | §64 |
//! | | WAIT_AUTH | auth failure | CLOSED | §64 |
//! | | READY | fatal error or socket close | CLOSED | §64 |
//! | per-Resource sync | CLOSED | RESOURCE_OPEN | OPENING | §65 |
//! | | OPENING | RESOURCE_OPENED | CONTROL_SYNC | §65 |
//! | | CONTROL_SYNC | multiple valid Control Heads | CONTROL_CONFLICT | §65, §42 |
//! | | CONTROL_SYNC | Control Chain complete | KEY_SYNC | §65 |
//! | | KEY_SYNC | required DEK available | DATA_SYNC | §65 |
//! | | KEY_SYNC | Key Package unavailable | KEY_BLOCKED | §65 |
//! | | KEY_BLOCKED | package arrives | KEY_SYNC | §65 |
//! | | DATA_SYNC | snapshot/replay reaches known frontier | LIVE | §65 |
//! | | LIVE | missing ranges detected | DATA_SYNC | §65 |
//! | | LIVE | new Control Record received | CONTROL_SYNC | §65 |
//! | | every state but CLOSED | RESOURCE_CLOSE / connection lost | CLOSED | §65 |
//! | | CONTROL_CONFLICT | manual close | CLOSED | §65 |
//!
//! [`server_accepts`] applies the §64 rule that a server rejects Resource,
//! Control, Data, Key and Snapshot messages before `READY` with
//! `AUTHORIZATION_FAILED`; `PING`, `PONG` and `ERROR` are allowed in every
//! state.

use crate::base::Error;

fn illegal<S: std::fmt::Debug, E: std::fmt::Debug>(state: S, event: E) -> Error {
    Error::IllegalTransition {
        state: format!("{state:?}"),
        event: format!("{event:?}"),
    }
}

/// Client connection states (§63).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ClientConnection {
    Disconnected,
    Connecting,
    Negotiating,
    Authenticating,
    Ready,
}

/// Client connection events (§63).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ClientConnectionEvent {
    OpenWebSocket,
    SubprotocolAccepted,
    ConnectionFailed,
    HelloChallenge,
    AuthReady,
    OpenCloseResources,
    SocketClosed,
    FatalError,
    AuthFailure,
}

impl ClientConnection {
    /// The §63 transition for `event`.
    pub fn transition(self, event: ClientConnectionEvent) -> Result<ClientConnection, Error> {
        use ClientConnection as S;
        use ClientConnectionEvent as E;
        match (self, event) {
            (S::Disconnected, E::OpenWebSocket) => Ok(S::Connecting),
            (S::Connecting, E::SubprotocolAccepted) => Ok(S::Negotiating),
            (S::Connecting, E::ConnectionFailed) => Ok(S::Disconnected),
            (S::Negotiating, E::HelloChallenge) => Ok(S::Authenticating),
            (S::Authenticating, E::AuthReady) => Ok(S::Ready),
            (S::Ready, E::OpenCloseResources) => Ok(S::Ready),
            (S::Ready, E::SocketClosed) => Ok(S::Disconnected),
            (S::Negotiating, E::FatalError) => Ok(S::Disconnected),
            (S::Authenticating, E::AuthFailure) => Ok(S::Disconnected),
            (state, event) => Err(illegal(state, event)),
        }
    }
}

/// Server session states (§64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ServerSession {
    Accepted,
    WaitHello,
    WaitAuth,
    Ready,
    Closed,
}

/// Server session events (§64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ServerSessionEvent {
    Start,
    ValidHello,
    ValidAuth,
    Message,
    ProtocolViolation,
    AuthFailure,
    FatalErrorOrClose,
}

impl ServerSession {
    /// The §64 transition for `event`.
    pub fn transition(self, event: ServerSessionEvent) -> Result<ServerSession, Error> {
        use ServerSession as S;
        use ServerSessionEvent as E;
        match (self, event) {
            (S::Accepted, E::Start) => Ok(S::WaitHello),
            (S::WaitHello, E::ValidHello) => Ok(S::WaitAuth),
            (S::WaitAuth, E::ValidAuth) => Ok(S::Ready),
            (S::Ready, E::Message) => Ok(S::Ready),
            (S::WaitHello, E::ProtocolViolation) => Ok(S::Closed),
            (S::WaitAuth, E::AuthFailure) => Ok(S::Closed),
            (S::Ready, E::FatalErrorOrClose) => Ok(S::Closed),
            (state, event) => Err(illegal(state, event)),
        }
    }
}

/// Whether a server in `state` may process a message of `message_type`:
/// Resource, Control, Data, Key and Snapshot messages (§33.2–§33.6) are
/// rejected before `READY` (§64). `PING`, `PONG` and `ERROR` pass in every
/// state; other types are left to the handshake.
pub fn server_accepts(state: ServerSession, message_type: u64) -> Result<(), Error> {
    let gated = matches!(message_type, 10..=14 | 20..=23 | 30..=33 | 40..=42 | 50..=52);
    if gated && state != ServerSession::Ready {
        Err(Error::SessionNotReady(message_type))
    } else {
        Ok(())
    }
}

/// Per-Resource client sync states (§65).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ResourceSync {
    Closed,
    Opening,
    ControlSync,
    ControlConflict,
    KeySync,
    KeyBlocked,
    DataSync,
    Live,
}

/// Per-Resource client sync events (§65).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ResourceSyncEvent {
    ResourceOpen,
    ResourceOpened,
    MultipleControlHeads,
    ControlChainComplete,
    DekAvailable,
    KeyPackageUnavailable,
    KeyPackageArrived,
    FrontierReached,
    MissingRanges,
    NewControlRecord,
    CloseOrConnectionLost,
    ManualClose,
}

impl ResourceSync {
    /// The §65 transition for `event`.
    pub fn transition(self, event: ResourceSyncEvent) -> Result<ResourceSync, Error> {
        use ResourceSync as S;
        use ResourceSyncEvent as E;
        match (self, event) {
            (S::Closed, E::ResourceOpen) => Ok(S::Opening),
            (S::Opening, E::ResourceOpened) => Ok(S::ControlSync),
            (S::ControlSync, E::MultipleControlHeads) => Ok(S::ControlConflict),
            (S::ControlSync, E::ControlChainComplete) => Ok(S::KeySync),
            (S::KeySync, E::DekAvailable) => Ok(S::DataSync),
            (S::KeySync, E::KeyPackageUnavailable) => Ok(S::KeyBlocked),
            (S::KeyBlocked, E::KeyPackageArrived) => Ok(S::KeySync),
            (S::DataSync, E::FrontierReached) => Ok(S::Live),
            (S::Live, E::MissingRanges) => Ok(S::DataSync),
            (S::Live, E::NewControlRecord) => Ok(S::ControlSync),
            // §65: every state moves to CLOSED on RESOURCE_CLOSE or when the
            // connection is lost. The diagram draws no CLOSED → CLOSED edge.
            (S::Closed, E::CloseOrConnectionLost) => Err(illegal(S::Closed, event)),
            (_, E::CloseOrConnectionLost) => Ok(S::Closed),
            (S::ControlConflict, E::ManualClose) => Ok(S::Closed),
            (state, event) => Err(illegal(state, event)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_connection_happy_path_and_failures() {
        use ClientConnection as S;
        use ClientConnectionEvent as E;
        let mut state = S::Disconnected;
        for event in [
            E::OpenWebSocket,
            E::SubprotocolAccepted,
            E::HelloChallenge,
            E::AuthReady,
        ] {
            state = state.transition(event).unwrap();
        }
        assert_eq!(state, S::Ready);
        assert_eq!(state.transition(E::OpenCloseResources), Ok(S::Ready));
        assert_eq!(state.transition(E::SocketClosed), Ok(S::Disconnected));
        assert_eq!(
            S::Authenticating.transition(E::AuthFailure),
            Ok(S::Disconnected)
        );
        // §63 (G-SM3): CONNECTING fails back to DISCONNECTED.
        assert_eq!(
            S::Connecting.transition(E::ConnectionFailed),
            Ok(S::Disconnected)
        );
        let err = S::Connecting.transition(E::AuthReady).unwrap_err();
        assert!(matches!(err, Error::IllegalTransition { .. }));
        assert_eq!(err.wire_code(), None);
    }

    #[test]
    fn server_session_and_pre_ready_gate() {
        use ServerSession as S;
        use ServerSessionEvent as E;
        let mut state = S::Accepted;
        for event in [E::Start, E::ValidHello, E::ValidAuth] {
            assert_eq!(server_accepts(state, 12), Err(Error::SessionNotReady(12)));
            state = state.transition(event).unwrap();
        }
        assert_eq!(state, S::Ready);
        for code in [10, 14, 20, 23, 30, 33, 40, 42, 50, 52] {
            assert_eq!(server_accepts(S::Ready, code), Ok(()), "{code}");
            assert!(server_accepts(S::WaitAuth, code).is_err(), "{code}");
        }
        for code in [0, 2, 5, 90] {
            assert_eq!(server_accepts(S::WaitHello, code), Ok(()), "{code}");
        }
        // §64 (G-SM4): PING, PONG and ERROR in every state.
        for state in [S::Accepted, S::WaitHello, S::WaitAuth, S::Ready, S::Closed] {
            for code in [5, 6, 4] {
                assert_eq!(server_accepts(state, code), Ok(()), "{state:?} {code}");
            }
        }
        let err = server_accepts(S::WaitHello, 33).unwrap_err();
        assert_eq!(err.wire_code().unwrap().name(), "AUTHORIZATION_FAILED");
        assert_eq!(S::WaitAuth.transition(E::AuthFailure), Ok(S::Closed));
        assert!(S::WaitHello.transition(E::ValidAuth).is_err());
    }

    #[test]
    fn resource_sync_paths() {
        use ResourceSync as S;
        use ResourceSyncEvent as E;
        let mut state = S::Closed;
        for (event, expected) in [
            (E::ResourceOpen, S::Opening),
            (E::ResourceOpened, S::ControlSync),
            (E::ControlChainComplete, S::KeySync),
            (E::KeyPackageUnavailable, S::KeyBlocked),
            (E::KeyPackageArrived, S::KeySync),
            (E::DekAvailable, S::DataSync),
            (E::FrontierReached, S::Live),
            (E::MissingRanges, S::DataSync),
            (E::FrontierReached, S::Live),
            (E::NewControlRecord, S::ControlSync),
            (E::MultipleControlHeads, S::ControlConflict),
            (E::ManualClose, S::Closed),
        ] {
            state = state.transition(event).unwrap();
            assert_eq!(state, expected, "{event:?}");
        }
        assert!(S::ControlConflict
            .transition(E::ControlChainComplete)
            .is_err());
        // §65 (G-SM1): every state closes on RESOURCE_CLOSE or connection
        // loss.
        for state in [
            S::Opening,
            S::ControlSync,
            S::ControlConflict,
            S::KeySync,
            S::KeyBlocked,
            S::DataSync,
            S::Live,
        ] {
            assert_eq!(
                state.transition(E::CloseOrConnectionLost),
                Ok(S::Closed),
                "{state:?}"
            );
        }
        assert!(S::Closed.transition(E::CloseOrConnectionLost).is_err());
    }
}
