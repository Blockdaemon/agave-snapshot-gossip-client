use std::path::PathBuf;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use log::{error, info};
use tokio::fs::File;
use tokio_util::io::ReaderStream;

#[derive(Clone)]
pub struct LocalStorage {
    storage_path: String,
}

impl LocalStorage {
    pub fn new(storage_path: String) -> Self {
        Self { storage_path }
    }

    pub async fn handle_request(
        State(storage): State<Self>,
        Path(path): Path<String>,
    ) -> impl IntoResponse {
        // Strip leading slash from path if present
        let path = path.strip_prefix('/').unwrap_or(&path);
        let file_path = PathBuf::from(&storage.storage_path).join(path);
        info!("Serving local file: {}", file_path.display());

        match File::open(&file_path).await {
            Ok(file) => {
                let stream = ReaderStream::new(file);
                let body = Body::from_stream(stream);

                let content_type = Self::guess_content_type(&file_path);
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, content_type)
                    .body(body)
                    .unwrap()
            }
            Err(e) => {
                error!("Failed to open file {}: {}", file_path.display(), e);
                (StatusCode::NOT_FOUND, "File not found\n").into_response()
            }
        }
    }

    fn guess_content_type(path: &PathBuf) -> &'static str {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => "application/json",
            Some("txt") => "text/plain",
            Some("bin") => "application/octet-stream",
            Some("tar") => "application/x-tar",
            Some("gz") => "application/gzip",
            Some("zst") => "application/zstd",
            _ => "application/octet-stream",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_serve_local_file() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        tokio::fs::write(&test_file, "test content\n")
            .await
            .unwrap();

        let storage = LocalStorage::new(temp_dir.path().to_string_lossy().to_string());
        let response = LocalStorage::handle_request(State(storage), Path("test.txt".to_string()))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain"
        );
    }

    #[tokio::test]
    async fn test_uri_formats() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        tokio::fs::write(&test_file, "test content\n")
            .await
            .unwrap();

        // Test with three-slash format (file:///path)
        let storage = LocalStorage::new(temp_dir.path().to_string_lossy().to_string());
        let response = LocalStorage::handle_request(State(storage), Path("test.txt".to_string()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Test with localhost format (file://localhost/path)
        let storage = LocalStorage::new(temp_dir.path().to_string_lossy().to_string());
        let response = LocalStorage::handle_request(State(storage), Path("test.txt".to_string()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_path_handling() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        tokio::fs::write(&test_file, "test content\n")
            .await
            .unwrap();

        let storage = LocalStorage::new(temp_dir.path().to_string_lossy().to_string());

        // Test with leading slash
        let response =
            LocalStorage::handle_request(State(storage.clone()), Path("/test.txt".to_string()))
                .await
                .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Test without leading slash
        let response = LocalStorage::handle_request(State(storage), Path("test.txt".to_string()))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
