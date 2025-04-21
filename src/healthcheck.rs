use axum::handler::Handler;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde_json::json;

use crate::constants::HEALTH_CHECK_MIN_GOSSIP_PEERS;
use crate::rpc::AppState;

pub async fn health_check(State(app_state): State<AppState>) -> impl IntoResponse {
    let atomic_state = &app_state.atomic_state;

    let gossip_enabled = !app_state.disable_gossip;
    let num_peers = if gossip_enabled {
        atomic_state.get_num_peers()
    } else {
        0
    };

    let gossip_status = if !gossip_enabled {
        "disabled"
    } else if num_peers >= (HEALTH_CHECK_MIN_GOSSIP_PEERS as i64) {
        "ok"
    } else {
        "degraded"
    };

    let response_json = json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "build_timestamp": env!("BUILD_TIMESTAMP"),
        "git_sha": env!("GIT_SHA"),
        "git_tag": env!("GIT_TAG"),
        "gossip_status": gossip_status,
        "gossip_peers": num_peers,
    });

    (
        StatusCode::OK,
        [("Content-Type", "application/json")],
        response_json.to_string() + "\n",
    )
}

pub fn health_check_handler() -> impl Handler<(), AppState> {
    get(health_check)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::atomic_state::AtomicState;
    use crate::scraper::MetadataScraper;
    use axum::Router;
    use axum_test::TestServer;

    use super::*;

    fn create_test_app_state() -> AppState {
        let atomic_state = AtomicState::new();
        let disable_gossip = false;
        let enable_proxy = false;
        let serve_local = false;
        let scraper = Arc::new(MetadataScraper::new(None, None));
        AppState {
            atomic_state,
            scraper,
            disable_gossip,
            enable_proxy,
            serve_local,
        }
    }

    #[tokio::test]
    async fn test_health_check_base() {
        let app_state = create_test_app_state();
        let app = Router::new()
            .route("/health", get(health_check_handler()))
            .with_state(app_state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let json: serde_json::Value = response.json();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["gossip_status"], "degraded");
        assert_eq!(json["gossip_peers"], 0);
        assert!(json["version"].is_string());
    }

    #[tokio::test]
    async fn test_health_check_gossip_ok() {
        let app_state = create_test_app_state();
        app_state
            .atomic_state
            .set_num_peers(HEALTH_CHECK_MIN_GOSSIP_PEERS as i64);
        let app = Router::new()
            .route("/health", get(health_check_handler()))
            .with_state(app_state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        let json: serde_json::Value = response.json();
        assert_eq!(json["gossip_status"], "ok");
        assert_eq!(json["gossip_peers"], HEALTH_CHECK_MIN_GOSSIP_PEERS);
    }

    #[tokio::test]
    async fn test_health_check_gossip_disabled() {
        let app_state_disabled = AppState {
            disable_gossip: true,
            ..create_test_app_state()
        };
        app_state_disabled
            .atomic_state
            .set_num_peers((HEALTH_CHECK_MIN_GOSSIP_PEERS + 5) as i64);

        let app = Router::new()
            .route("/health", get(health_check_handler()))
            .with_state(app_state_disabled);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        let json: serde_json::Value = response.json();
        assert_eq!(json["gossip_status"], "disabled");
        assert_eq!(json["gossip_peers"], 0);
    }
}
