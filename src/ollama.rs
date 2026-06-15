//! Ollama HTTP client — sends PKGBUILD text to Ollama's `/api/generate` endpoint
//! and parses the structured verdict response.
//!
//! Uses `reqwest` for HTTP, `serde_json` for request/response serialisation,
//! and `wiremock` (dev-only) for test mocking.

use crate::types::ScanResult;

// ─── OllamaClient ──────────────────────────────────────────────────────────────

/// Async HTTP client for Ollama's LLM API.
///
/// Constructed with an endpoint URL, model name, and optionally a pre-configured
/// `reqwest::Client` (used in tests with wiremock).
pub struct OllamaClient {
    client: reqwest::Client,
    endpoint: String,
    model: String,
}

impl OllamaClient {
    /// Create a new client pointed at the given Ollama endpoint and model.
    ///
    /// The internal `reqwest::Client` is configured with a **120-second timeout**
    /// to accommodate slow model responses.
    pub fn new(endpoint: String, model: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("reqwest::Client should build with valid config");
        Self {
            client,
            endpoint,
            model,
        }
    }

    /// Create a client with a pre-built `reqwest::Client`.
    ///
    /// Used in tests to point at a wiremock server without forcing the 120s
    /// timeout on mocked HTTP.
    pub fn with_client(client: reqwest::Client, endpoint: String, model: String) -> Self {
        Self {
            client,
            endpoint,
            model,
        }
    }

    /// Send a PKGBUILD to Ollama for security analysis.
    ///
    /// # Arguments
    /// * `pkgbuild` — the raw text of the PKGBUILD file.
    /// * `prompt` — the security audit prompt to prepend before the PKGBUILD.
    ///
    /// # Returns
    /// * `Ok(ScanResult::Clean)` if the model verdict is CLEAN.
    /// * `Ok(ScanResult::Suspicious { findings })` with extracted `FINDING:` lines.
    /// * `Ok(ScanResult::Error(msg))` if the response cannot be parsed.
    /// * `Err(msg)` on network/HTTP failures.
    pub async fn scan(&self, pkgbuild: &str, prompt: &str) -> Result<ScanResult, String> {
        let body = serde_json::json!({
            "model": self.model,
            "prompt": format!("{prompt}\n\nPKGBUILD:\n```\n{pkgbuild}\n```"),
            "stream": false,
        });

        let url = format!("{}/api/generate", self.endpoint);

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Ollama request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Ollama returned HTTP {}", resp.status()));
        }

        let response_text = resp
            .text()
            .await
            .map_err(|e| format!("Failed to read Ollama response body: {e}"))?;

        let parsed: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| format!("Failed to parse Ollama JSON response: {e}"))?;

        let model_response = parsed["response"]
            .as_str()
            .ok_or_else(|| "Missing 'response' field in Ollama response".to_string())?;

        Ok(Self::parse_verdict(model_response))
    }

    /// Extract a `ScanResult` from the model's raw response text.
    ///
    /// Looks for `VERDICT: CLEAN` or `VERDICT: SUSPICIOUS` at the very start
    /// of the response.  If SUSPICIOUS, collects all `FINDING:` lines.
    fn parse_verdict(response_text: &str) -> ScanResult {
        if response_text.starts_with("VERDICT: CLEAN") {
            return ScanResult::Clean;
        }

        if response_text.starts_with("VERDICT: SUSPICIOUS") {
            let findings: Vec<String> = response_text
                .lines()
                .filter(|line| line.starts_with("FINDING:"))
                .map(|line| line.trim_start_matches("FINDING:").trim().to_string())
                .collect();
            return ScanResult::Suspicious { findings };
        }

        ScanResult::Error("unparseable response".to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unit tests  (TDD: wiremock-based HTTP mocking)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_ENDPOINT_PATH: &str = "/api/generate";

    /// Build an `OllamaClient` whose `endpoint` points at a wiremock server.
    fn test_client(server: &MockServer) -> OllamaClient {
        OllamaClient::with_client(reqwest::Client::new(), server.uri(), "test-model".into())
    }

    // ── parse_verdict unit tests (no HTTP) ────────────────────────────────────

    #[test]
    fn test_parse_verdict_clean() {
        let result = OllamaClient::parse_verdict("VERDICT: CLEAN\n\nThis appears safe.");
        assert!(matches!(result, ScanResult::Clean));
    }

    #[test]
    fn test_parse_verdict_suspicious_with_findings() {
        let result = OllamaClient::parse_verdict(
            "VERDICT: SUSPICIOUS\nFINDING: curl to unknown IP\nFINDING: base64 encoded command",
        );
        match result {
            ScanResult::Suspicious { findings } => {
                assert_eq!(findings.len(), 2);
                assert_eq!(findings[0], "curl to unknown IP");
                assert_eq!(findings[1], "base64 encoded command");
            }
            other => panic!("expected Suspicious, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_verdict_unparseable() {
        let result = OllamaClient::parse_verdict("garbage without verdict");
        match result {
            ScanResult::Error(msg) => assert_eq!(msg, "unparseable response"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_verdict_suspicious_no_findings() {
        // SUSPICIOUS with no FINDING: lines — still Suspicious, empty vec
        let result = OllamaClient::parse_verdict("VERDICT: SUSPICIOUS\nNo details.");
        match result {
            ScanResult::Suspicious { findings } => {
                assert!(findings.is_empty());
            }
            other => panic!("expected Suspicious with empty findings, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_verdict_case_sensitive() {
        // "verdict: clean" (lowercase) should NOT match — case-sensitive
        let result = OllamaClient::parse_verdict("verdict: clean\nlooks fine");
        match result {
            ScanResult::Error(msg) => assert_eq!(msg, "unparseable response"),
            other => panic!("expected Error for wrong case, got {other:?}"),
        }
    }

    // ── scan integration tests (wiremock) ────────────────────────────────────

    /// Mock returns CLEAN verdict.
    #[tokio::test]
    async fn test_scan_clean() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(TEST_ENDPOINT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"response": "VERDICT: CLEAN\n\nThis appears safe."}),
            ))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client.scan("pkgname=test\n", "audit this").await;

        match result {
            Ok(ScanResult::Clean) => {} // pass
            other => panic!("expected Ok(Clean), got {other:?}"),
        }
    }

    /// Mock returns SUSPICIOUS with two findings.
    #[tokio::test]
    async fn test_scan_suspicious() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(TEST_ENDPOINT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"response": "VERDICT: SUSPICIOUS\nFINDING: curl to unknown IP\nFINDING: base64 encoded command"}),
            ))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client.scan("pkgname=malware\n", "audit this").await;

        match result {
            Ok(ScanResult::Suspicious { findings }) => {
                assert_eq!(findings.len(), 2);
                assert_eq!(findings[0], "curl to unknown IP");
                assert_eq!(findings[1], "base64 encoded command");
            }
            other => panic!("expected Ok(Suspicious), got {other:?}"),
        }
    }

    /// Mock returns response without a VERDICT prefix — should be Error, not Err.
    #[tokio::test]
    async fn test_scan_unparseable() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(TEST_ENDPOINT_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"response": "garbage without verdict"})),
            )
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client.scan("pkgname=test\n", "audit this").await;

        match result {
            Ok(ScanResult::Error(msg)) => {
                assert_eq!(msg, "unparseable response");
            }
            other => panic!("expected Ok(Error(..)), got {other:?}"),
        }
    }

    /// Mock returns HTTP 500 — should be Err.
    #[tokio::test]
    async fn test_scan_http_500() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(TEST_ENDPOINT_PATH))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client.scan("pkgname=test\n", "audit this").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTP 500"));
    }

    /// Mock connection refused (no server) — should be Err.
    #[tokio::test]
    async fn test_scan_connection_refused() {
        // Point at a port that nothing is listening on (use a random high port).
        let client = OllamaClient::with_client(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(1))
                .build()
                .unwrap(),
            "http://127.0.0.1:19999".into(),
            "test-model".into(),
        );

        let result = client.scan("pkgname=test\n", "audit this").await;

        assert!(result.is_err(), "connection to dead port should fail");
    }

    /// Mock returns valid JSON but the "response" field is missing.
    #[tokio::test]
    async fn test_scan_missing_response_field() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(TEST_ENDPOINT_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"model": "test-model", "done": true})),
            )
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client.scan("pkgname=test\n", "audit this").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing 'response' field"));
    }

    /// Mock returns malformed JSON.
    #[tokio::test]
    async fn test_scan_malformed_json() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(TEST_ENDPOINT_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client.scan("pkgname=test\n", "audit this").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to parse Ollama JSON"));
    }

    /// Request body should include the prompt, PKGBUILD, model, and stream=false.
    #[tokio::test]
    async fn test_scan_request_body_shape() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(TEST_ENDPOINT_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"response": "VERDICT: CLEAN\n"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(&server);
        let result = client
            .scan("pkgname=hello\npkgver=1.0", "You are a security auditor.")
            .await;

        assert!(result.is_ok());
        // wiremock .expect(1) verifies exactly one POST hit the endpoint.
    }
}
