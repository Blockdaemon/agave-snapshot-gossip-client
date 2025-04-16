use axum::{http::StatusCode, response::IntoResponse, routing::get, Router};
use serde_json::json;

pub async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "application/json")],
        json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "build_timestamp": env!("BUILD_TIMESTAMP"),
            "git_sha": env!("GIT_SHA"),
            "git_tag": env!("GIT_TAG")
        })
        .to_string()
            + "\n",
    )
}

pub fn add_health_check_route(router: Router) -> Router {
    router.route("/health", get(health_check))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_health_check() {
        let app = add_health_check_route(Router::new());
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let json: serde_json::Value = response.json();
        assert_eq!(json["status"], "ok");
        assert!(json["version"].is_string());
        assert!(json["build_timestamp"].is_string());
        assert!(json["git_sha"].is_string());
        assert!(json["git_tag"].is_string());
    }
}
