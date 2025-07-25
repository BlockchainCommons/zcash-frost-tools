use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use reqwest::StatusCode;
use uuid::Uuid;
use xeddsa::{xed25519, Verify as _};

use crate::{
    state::{Session, SessionParticipant, SharedState, SESSION_TIMEOUT},
    user::User,
};
use frost_client::api::*;

/// An Error which implements IntoResponse.
/// Required since Error is defined in another crate.
#[derive(Debug)]
pub(crate) struct IntoResponseError(Error);

impl IntoResponse for IntoResponseError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Into::<LowError>::into(self.0)),
        )
            .into_response()
    }
}

impl From<Error> for IntoResponseError {
    fn from(err: Error) -> Self {
        IntoResponseError(err)
    }
}

/// Implement the challenge API.
#[tracing::instrument(level = "debug", err(Debug), skip(state))]
pub(crate) async fn challenge(
    State(state): State<SharedState>,
) -> Result<Json<ChallengeOutput>, IntoResponseError> {
    // Create new challenge.
    let challenge = Uuid::new_v4();

    state.challenges.write().unwrap().insert(challenge);

    let output = ChallengeOutput { challenge };
    Ok(Json(output))
}

/// Implement the key_login API.
#[tracing::instrument(level = "debug", err(Debug), skip(state, args))]
pub(crate) async fn login(
    State(state): State<SharedState>,
    Json(args): Json<LoginArgs>,
) -> Result<Json<LoginOutput>, IntoResponseError> {
    // Check if the user sent the credentials
    if args.signature.is_empty() || args.pubkey.0.is_empty() {
        return Err(Error::InvalidArgument("signature or pubkey".into()).into());
    }

    let pubkey = TryInto::<[u8; 32]>::try_into(args.pubkey.0.clone())
        .map_err(|_| Error::InvalidArgument("pubkey".into()))?;
    let pubkey = xed25519::PublicKey(pubkey);
    let signature = TryInto::<[u8; 64]>::try_into(args.signature)
        .map_err(|_| Error::InvalidArgument("signature".into()))?;
    pubkey
        .verify(args.challenge.as_bytes(), &signature)
        .map_err(|_| Error::Unauthorized)?;

    let mut challenges = state.challenges.write().unwrap();
    if !challenges.remove(&args.challenge) {
        return Err(Error::Unauthorized.into());
    }
    drop(challenges);

    let access_token = Uuid::new_v4();

    let mut access_tokens = state.access_tokens.write().unwrap();
    access_tokens.insert(access_token, args.pubkey);

    let token = LoginOutput { access_token };

    Ok(Json(token))
}

/// Implement the logout API.
#[tracing::instrument(level = "debug", ret, err(Debug), skip(state, user))]
pub(crate) async fn logout(
    State(state): State<SharedState>,
    user: User,
) -> Result<Json<()>, IntoResponseError> {
    state
        .access_tokens
        .write()
        .unwrap()
        .remove(&user.current_token);
    Ok(Json(()))
}

/// Implement the create_new_session API.
#[tracing::instrument(level = "debug", ret, err(Debug), skip(state, user))]
pub(crate) async fn create_new_session(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<CreateNewSessionArgs>,
) -> Result<Json<CreateNewSessionOutput>, IntoResponseError> {
    if args.message_count == 0 {
        return Err(Error::InvalidArgument("message_count".into()).into());
    }

    // Create new session object.
    let id = Uuid::new_v4();

    let mut sessions = state.sessions.sessions.write().unwrap();
    let mut sessions_by_pubkey = state.sessions.sessions_by_pubkey.write().unwrap();

    // Save session ID in global state
    for pubkey in &args.pubkeys {
        sessions_by_pubkey
            .entry(pubkey.clone())
            .or_default()
            .insert(id);
    }
    // Also add the coordinator, since they don't have to be a participant
    sessions_by_pubkey
        .entry(user.pubkey.clone())
        .or_default()
        .insert(id);
    // Create Session object
    let session = Session {
        pubkeys: args.pubkeys.clone(),
        coordinator_pubkey: user.pubkey,
        message_count: args.message_count,
        queue: Default::default(),
    };
    // Save session into global state.
    sessions.insert(id, session);

    let user = CreateNewSessionOutput { session_id: id };
    Ok(Json(user))
}

/// Implement the create_new_session API.
#[tracing::instrument(level = "debug", ret, err(Debug), skip(state, user))]
pub(crate) async fn list_sessions(
    State(state): State<SharedState>,
    user: User,
) -> Result<Json<ListSessionsOutput>, IntoResponseError> {
    let sessions_by_pubkey = state.sessions.sessions_by_pubkey.read().unwrap();

    let session_ids = sessions_by_pubkey
        .get(&user.pubkey)
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();

    Ok(Json(ListSessionsOutput { session_ids }))
}

/// Implement the get_session_info API
#[tracing::instrument(level = "debug", ret, err(Debug), skip(state, user))]
pub(crate) async fn get_session_info(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<GetSessionInfoArgs>,
) -> Result<Json<GetSessionInfoOutput>, IntoResponseError> {
    let sessions = state.sessions.sessions.read().unwrap();
    let sessions_by_pubkey = state.sessions.sessions_by_pubkey.read().unwrap();

    let user_sessions = sessions_by_pubkey
        .get(&user.pubkey)
        .ok_or(Error::SessionNotFound)?;

    if !user_sessions.contains(&args.session_id) {
        return Err(Error::SessionNotFound.into());
    }

    let session = sessions
        .get(&args.session_id)
        .ok_or(Error::SessionNotFound)?;

    Ok(Json(GetSessionInfoOutput {
        message_count: session.message_count,
        pubkeys: session.pubkeys.clone(),
        coordinator_pubkey: session.coordinator_pubkey.clone(),
    }))
}

/// Implement the send API
#[tracing::instrument(level = "debug", ret, err(Debug), skip(state, user))]
pub(crate) async fn send(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<SendArgs>,
) -> Result<(), IntoResponseError> {
    if args.msg.len() > MAX_MSG_SIZE {
        return Err(Error::InvalidArgument("msg is too big".into()).into());
    }

    // Get the mutex lock to read and write from the state
    let mut sessions = state.sessions.sessions.write().unwrap();

    let session = sessions
        .get_mut(&args.session_id)
        .ok_or(Error::SessionNotFound)?;

    let recipients = if args.recipients.is_empty() {
        vec![SessionParticipant::Coordinator]
    } else {
        args.recipients
            .into_iter()
            .map(SessionParticipant::Participant)
            .collect()
    };

    // Check if both the sender and the recipients are in the session
    if (!session.pubkeys.contains(&user.pubkey) && session.coordinator_pubkey != user.pubkey)
        || recipients.iter().any(|p| match p {
            SessionParticipant::Coordinator => false,
            SessionParticipant::Participant(public_key) => !session.pubkeys.contains(public_key),
        })
    {
        return Err(Error::NotInSession.into());
    }

    for recipient in &recipients {
        session
            .queue
            .entry(recipient.clone())
            .or_default()
            .push_back(Msg {
                sender: user.pubkey.clone(),
                msg: args.msg.clone(),
            });
    }
    sessions.update_timeout(&args.session_id, SESSION_TIMEOUT);

    Ok(())
}

/// Implement the recv API
#[tracing::instrument(level = "debug", ret, err(Debug), skip(state, user))]
pub(crate) async fn receive(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<ReceiveArgs>,
) -> Result<Json<ReceiveOutput>, IntoResponseError> {
    // Get the mutex lock to read and write from the state
    let mut sessions = state.sessions.sessions.write().unwrap();

    let session = sessions
        .get_mut(&args.session_id)
        .ok_or(Error::SessionNotFound)?;

    // Check if both the sender and the recipients are in the session
    if !session.pubkeys.contains(&user.pubkey) && session.coordinator_pubkey != user.pubkey {
        return Err(Error::NotInSession.into());
    }

    let participant = if user.pubkey == session.coordinator_pubkey && args.as_coordinator {
        SessionParticipant::Coordinator
    } else {
        SessionParticipant::Participant(user.pubkey)
    };

    let msgs = if session.queue.contains_key(&participant) {
        let msgs = session
            .queue
            .entry(participant)
            .or_default()
            .drain(..)
            .collect();
        msgs
    } else {
        vec![]
    };
    // If there are no new messages, we don't want to renew the timeout.
    if !msgs.is_empty() {
        sessions.update_timeout(&args.session_id, SESSION_TIMEOUT);
    }

    Ok(Json(ReceiveOutput { msgs }))
}

/// Implement the close_session API.
#[tracing::instrument(level = "debug", ret, err(Debug), skip(state, user))]
pub(crate) async fn close_session(
    State(state): State<SharedState>,
    user: User,
    Json(args): Json<CloseSessionArgs>,
) -> Result<Json<()>, IntoResponseError> {
    let mut sessions = state.sessions.sessions.write().unwrap();
    let mut sessions_by_pubkey = state.sessions.sessions_by_pubkey.write().unwrap();

    let user_sessions = sessions_by_pubkey
        .get(&user.pubkey)
        .ok_or(Error::SessionNotFound)?;

    if !user_sessions.contains(&args.session_id) {
        return Err(Error::SessionNotFound.into());
    }

    let session = sessions
        .get(&args.session_id)
        .ok_or(Error::SessionNotFound)?;

    if session.coordinator_pubkey != user.pubkey {
        return Err(Error::NotCoordinator.into());
    }

    // Remove session from each participant list...
    for pubkey in session.pubkeys.clone() {
        if let Some(v) = sessions_by_pubkey.get_mut(&pubkey) {
            v.remove(&args.session_id);
        }
    }
    // And also remove from the coordinator's list
    // (might have been already removed if they are also a participant)
    if let Some(v) = sessions_by_pubkey.get_mut(&user.pubkey) {
        v.remove(&args.session_id);
    }
    sessions.remove(&args.session_id);
    Ok(Json(()))
}
