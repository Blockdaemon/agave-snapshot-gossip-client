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
        method: http::Method,
    ) -> impl IntoResponse {
        // Strip leading slash from path if present
        let path = path.strip_prefix('/').unwrap_or(&path);
        let file_path = PathBuf::from(&storage.storage_path).join(path);
        info!(
            "Serving local file: {} (method: {})",
            file_path.display(),
            method
        );

        match File::open(&file_path).await {
            Ok(file) => {
                // Check if it's actually a regular file, not a directory
                match tokio::fs::metadata(&file_path).await {
                    Ok(metadata) => {
                        if !metadata.is_file() {
                            error!("Path is not a regular file: {}", file_path.display());
                            return (StatusCode::NOT_FOUND, "File not found\n").into_response();
                        }

                        let content_type = Self::guess_content_type(&file_path);
                        let builder = Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, content_type)
                            .header(header::CONTENT_LENGTH, metadata.len().to_string());

                        if method == http::Method::HEAD {
                            // For HEAD requests, return headers without body
                            builder.body(Body::empty()).unwrap()
                        } else {
                            // For GET requests, stream the file content
                            let stream = ReaderStream::new(file);
                            let body = Body::from_stream(stream);
                            builder.body(body).unwrap()
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to get metadata for file {}: {}",
                            file_path.display(),
                            e
                        );
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error\n")
                            .into_response()
                    }
                }
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
        let response = LocalStorage::handle_request(
            State(storage),
            Path("test.txt".to_string()),
            http::Method::GET,
        )
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
        let response = LocalStorage::handle_request(
            State(storage),
            Path("test.txt".to_string()),
            http::Method::GET,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Test with localhost format (file://localhost/path)
        let storage = LocalStorage::new(temp_dir.path().to_string_lossy().to_string());
        let response = LocalStorage::handle_request(
            State(storage),
            Path("test.txt".to_string()),
            http::Method::GET,
        )
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
        let response = LocalStorage::handle_request(
            State(storage.clone()),
            Path("/test.txt".to_string()),
            http::Method::GET,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Test without leading slash
        let response = LocalStorage::handle_request(
            State(storage),
            Path("test.txt".to_string()),
            http::Method::GET,
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_head_request_content_type() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.json");
        tokio::fs::write(&test_file, r#"{"test": "data"}"#)
            .await
            .unwrap();

        // Test that guess_content_type works correctly for HEAD requests
        let content_type = LocalStorage::guess_content_type(&test_file);
        assert_eq!(content_type, "application/json");

        // Test with different file extensions
        let tar_file = temp_dir.path().join("snapshot.tar.gz");
        let content_type = LocalStorage::guess_content_type(&tar_file);
        assert_eq!(content_type, "application/gzip");

        let bin_file = temp_dir.path().join("data.bin");
        let content_type = LocalStorage::guess_content_type(&bin_file);
        assert_eq!(content_type, "application/octet-stream");

        let txt_file = temp_dir.path().join("readme.txt");
        let content_type = LocalStorage::guess_content_type(&txt_file);
        assert_eq!(content_type, "text/plain");
    }

    #[tokio::test]
    async fn test_head_request_metadata() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.bin");
        let test_content = b"test binary data";
        tokio::fs::write(&test_file, test_content).await.unwrap();

        // Test that we can get metadata for HEAD requests
        let metadata = tokio::fs::metadata(&test_file).await.unwrap();
        assert_eq!(metadata.len(), test_content.len() as u64);

        // Test that content type is correctly determined
        let content_type = LocalStorage::guess_content_type(&test_file);
        assert_eq!(content_type, "application/octet-stream");

        // Test with non-existent file (should return error)
        let non_existent_file = temp_dir.path().join("nonexistent.txt");
        let result = tokio::fs::metadata(&non_existent_file).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_head_request_handling() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let test_content = "test content\n";
        tokio::fs::write(&test_file, test_content).await.unwrap();

        let storage = LocalStorage::new(temp_dir.path().to_string_lossy().to_string());

        // Test HEAD request
        let response = LocalStorage::handle_request(
            State(storage.clone()),
            Path("test.txt".to_string()),
            http::Method::HEAD,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            test_content.len().to_string()
        );

        // Verify that HEAD response has no body
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body_bytes.len(), 0);

        // Test GET request for comparison
        let response = LocalStorage::handle_request(
            State(storage),
            Path("test.txt".to_string()),
            http::Method::GET,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain"
        );

        // Verify that GET response has body
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body_bytes, test_content.as_bytes());
    }

    #[tokio::test]
    async fn test_head_request_different_file_types() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_string_lossy().to_string());

        // Test JSON file
        let json_file = temp_dir.path().join("data.json");
        let json_content = r#"{"key": "value"}"#;
        tokio::fs::write(&json_file, json_content).await.unwrap();

        let response = LocalStorage::handle_request(
            State(storage.clone()),
            Path("data.json".to_string()),
            http::Method::HEAD,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            json_content.len().to_string()
        );

        // Test binary file
        let bin_file = temp_dir.path().join("data.bin");
        let bin_content = b"binary data";
        tokio::fs::write(&bin_file, bin_content).await.unwrap();

        let response = LocalStorage::handle_request(
            State(storage.clone()),
            Path("data.bin".to_string()),
            http::Method::HEAD,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            bin_content.len().to_string()
        );

        // Test compressed file
        let gz_file = temp_dir.path().join("archive.tar.gz");
        let gz_content = b"compressed data";
        tokio::fs::write(&gz_file, gz_content).await.unwrap();

        let response = LocalStorage::handle_request(
            State(storage),
            Path("archive.tar.gz".to_string()),
            http::Method::HEAD,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/gzip"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            gz_content.len().to_string()
        );
    }

    #[tokio::test]
    async fn test_head_request_errors() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_string_lossy().to_string());

        // Test HEAD request for non-existent file
        let response = LocalStorage::handle_request(
            State(storage.clone()),
            Path("nonexistent.txt".to_string()),
            http::Method::HEAD,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Test HEAD request with leading slash
        let response = LocalStorage::handle_request(
            State(storage.clone()),
            Path("/nonexistent.txt".to_string()),
            http::Method::HEAD,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Test HEAD request for directory (should fail)
        let subdir = temp_dir.path().join("subdir");
        tokio::fs::create_dir(&subdir).await.unwrap();

        let response = LocalStorage::handle_request(
            State(storage),
            Path("subdir".to_string()),
            http::Method::HEAD,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_head_vs_get_consistency() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_string_lossy().to_string());

        // Create a large file to test
        let large_file = temp_dir.path().join("large.bin");
        let large_content = vec![0u8; 1024]; // 1KB file
        tokio::fs::write(&large_file, &large_content).await.unwrap();

        // Test HEAD request
        let head_response = LocalStorage::handle_request(
            State(storage.clone()),
            Path("large.bin".to_string()),
            http::Method::HEAD,
        )
        .await
        .into_response();

        // Test GET request
        let get_response = LocalStorage::handle_request(
            State(storage),
            Path("large.bin".to_string()),
            http::Method::GET,
        )
        .await
        .into_response();

        // Verify that HEAD and GET return the same headers (except for body-related ones)
        assert_eq!(head_response.status(), get_response.status());
        assert_eq!(
            head_response.headers().get(header::CONTENT_TYPE),
            get_response.headers().get(header::CONTENT_TYPE)
        );
        assert_eq!(
            head_response.headers().get(header::CONTENT_LENGTH),
            get_response.headers().get(header::CONTENT_LENGTH)
        );

        // Verify that HEAD has no body while GET has the full body
        let head_body = axum::body::to_bytes(head_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let get_body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();

        assert_eq!(head_body.len(), 0);
        assert_eq!(get_body.len(), large_content.len());
        assert_eq!(get_body, large_content);
    }
}
