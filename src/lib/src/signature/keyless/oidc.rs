use crate::error::WSError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::env;

/// OIDC token for identity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcToken {
    /// JWT token string
    pub token: String,
    /// Identity (email, subject, etc.)
    pub identity: String,
    /// Issuer URL
    pub issuer: String,
}

impl OidcToken {
    /// Extract the `sub` claim from the OIDC token
    ///
    /// This is needed for proof of possession in Fulcio requests
    pub fn get_sub_claim(&self) -> Result<String, WSError> {
        // JWT tokens are base64-encoded and have three parts: header.payload.signature
        let parts: Vec<&str> = self.token.split('.').collect();
        if parts.len() != 3 {
            return Err(WSError::OidcError("Invalid JWT token format".to_string()));
        }

        // Decode the payload (second part)
        let payload = parts[1];
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| base64::prelude::BASE64_STANDARD.decode(payload))
            .map_err(|e| WSError::OidcError(format!("Failed to decode JWT payload: {}", e)))?;

        let payload_str = String::from_utf8(decoded)
            .map_err(|e| WSError::OidcError(format!("Invalid UTF-8 in JWT payload: {}", e)))?;

        // Parse JSON to extract sub claim
        let payload_json: serde_json::Value = serde_json::from_str(&payload_str)
            .map_err(|e| WSError::OidcError(format!("Failed to parse JWT payload: {}", e)))?;

        payload_json
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| WSError::OidcError("No 'sub' claim found in JWT token".to_string()))
    }
}

/// OIDC provider trait for obtaining identity tokens
pub trait OidcProvider: Send + Sync {
    /// Get an OIDC token from this provider
    fn get_token(&self) -> Result<OidcToken, WSError>;

    /// Provider name for logging
    fn name(&self) -> &str;
}

/// GitHub Actions OIDC provider
///
/// Uses the GitHub Actions OIDC token request mechanism to obtain
/// identity tokens for keyless signing in CI/CD workflows.
#[derive(Debug, Clone)]
pub struct GitHubOidcProvider {
    /// Request token from ACTIONS_ID_TOKEN_REQUEST_TOKEN env
    request_token: String,
    /// Request URL from ACTIONS_ID_TOKEN_REQUEST_URL env
    request_url: String,
}

impl GitHubOidcProvider {
    /// Create a new GitHub OIDC provider from environment variables
    pub fn new() -> Result<Self, WSError> {
        Self::from_env()
    }

    /// Create a GitHub OIDC provider from environment variables
    pub fn from_env() -> Result<Self, WSError> {
        let request_token = env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").map_err(|_| {
            WSError::OidcError(
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not found".to_string(),
            )
        })?;

        let request_url = env::var("ACTIONS_ID_TOKEN_REQUEST_URL").map_err(|_| {
            WSError::OidcError(
                "ACTIONS_ID_TOKEN_REQUEST_URL environment variable not found".to_string(),
            )
        })?;

        Ok(Self {
            request_token,
            request_url,
        })
    }

    /// Parse identity from JWT token (extract email or subject)
    fn parse_identity(token: &str) -> Result<String, WSError> {
        // JWT tokens are base64-encoded and have three parts: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(WSError::OidcError("Invalid JWT token format".to_string()));
        }

        // Decode the payload (second part)
        let payload = parts[1];
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| base64::prelude::BASE64_STANDARD.decode(payload))
            .map_err(|e| WSError::OidcError(format!("Failed to decode JWT payload: {}", e)))?;

        let payload_str = String::from_utf8(decoded)
            .map_err(|e| WSError::OidcError(format!("Invalid UTF-8 in JWT payload: {}", e)))?;

        // Parse JSON to extract identity fields
        let payload_json: serde_json::Value = serde_json::from_str(&payload_str)
            .map_err(|e| WSError::OidcError(format!("Failed to parse JWT payload: {}", e)))?;

        // Try to extract identity in order of preference: email > sub > actor
        if let Some(email) = payload_json.get("email").and_then(|v| v.as_str()) {
            Ok(email.to_string())
        } else if let Some(sub) = payload_json.get("sub").and_then(|v| v.as_str()) {
            Ok(sub.to_string())
        } else if let Some(actor) = payload_json.get("actor").and_then(|v| v.as_str()) {
            Ok(actor.to_string())
        } else {
            Err(WSError::OidcError(
                "No identity field found in JWT token".to_string(),
            ))
        }
    }

    /// Parse issuer from JWT token
    fn parse_issuer(token: &str) -> Result<String, WSError> {
        // JWT tokens are base64-encoded and have three parts: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(WSError::OidcError("Invalid JWT token format".to_string()));
        }

        // Decode the payload (second part)
        let payload = parts[1];
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .or_else(|_| base64::prelude::BASE64_STANDARD.decode(payload))
            .map_err(|e| WSError::OidcError(format!("Failed to decode JWT payload: {}", e)))?;

        let payload_str = String::from_utf8(decoded)
            .map_err(|e| WSError::OidcError(format!("Invalid UTF-8 in JWT payload: {}", e)))?;

        // Parse JSON to extract issuer
        let payload_json: serde_json::Value = serde_json::from_str(&payload_str)
            .map_err(|e| WSError::OidcError(format!("Failed to parse JWT payload: {}", e)))?;

        payload_json
            .get("iss")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| WSError::OidcError("No issuer field found in JWT token".to_string()))
    }
}

impl OidcProvider for GitHubOidcProvider {
    fn get_token(&self) -> Result<OidcToken, WSError> {
        // Get the token using platform-specific HTTP client
        let token = self.get_token_impl()?;

        // Parse identity and issuer from the token
        let identity = Self::parse_identity(&token)?;
        let issuer = Self::parse_issuer(&token)?;

        Ok(OidcToken {
            token,
            identity,
            issuer,
        })
    }

    fn name(&self) -> &str {
        "GitHub Actions"
    }
}

// Native implementation using ureq
#[cfg(not(target_os = "wasi"))]
impl GitHubOidcProvider {
    fn get_token_impl(&self) -> Result<String, WSError> {
        // GitHub's token endpoint expects a POST request with the bearer token
        // and an optional audience parameter
        let url = format!("{}&audience=sigstore", self.request_url);

        let response = ureq::get(&url)
            .header("Authorization", &format!("Bearer {}", self.request_token))
            .call()
            .map_err(|e| {
                WSError::OidcError(format!("Failed to retrieve OIDC token from GitHub: {}", e))
            })?;

        // Parse the JSON response
        let body = response.into_body().read_to_string().map_err(|e| {
            WSError::OidcError(format!("Failed to read response body: {}", e))
        })?;

        let json: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
            WSError::OidcError(format!("Failed to parse GitHub OIDC response: {}", e))
        })?;

        // Extract the token value
        json.get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                WSError::OidcError("No 'value' field in GitHub OIDC response".to_string())
            })
    }
}

// WASI implementation using wasi::http
#[cfg(target_os = "wasi")]
impl GitHubOidcProvider {
    fn get_token_impl(&self) -> Result<String, WSError> {
        use wasi::http::outgoing_handler;
        use wasi::http::types::{Fields, Method, OutgoingRequest, Scheme};

        // Parse the request URL to extract components
        let url_str = format!("{}&audience=sigstore", self.request_url);
        let url = url_str
            .strip_prefix("https://")
            .or_else(|| url_str.strip_prefix("http://"))
            .ok_or_else(|| WSError::OidcError("Invalid OIDC request URL scheme".to_string()))?;

        let (authority, path) = url
            .split_once('/')
            .map(|(auth, path)| (auth, format!("/{}", path)))
            .unwrap_or((url, "/".to_string()));

        // Create headers with Authorization
        let headers = Fields::new();
        let auth_value = format!("Bearer {}", self.request_token);
        headers
            .append(&"Authorization".to_string(), &auth_value.as_bytes().to_vec())
            .map_err(|_| WSError::OidcError("Failed to set Authorization header".to_string()))?;

        // Create outgoing request
        let request = OutgoingRequest::new(headers);
        request
            .set_method(&Method::Get)
            .map_err(|_| WSError::OidcError("Failed to set HTTP method".to_string()))?;
        request
            .set_scheme(Some(&Scheme::Https))
            .map_err(|_| WSError::OidcError("Failed to set HTTPS scheme".to_string()))?;
        request
            .set_authority(Some(authority))
            .map_err(|_| WSError::OidcError("Failed to set authority".to_string()))?;
        request
            .set_path_with_query(Some(&path))
            .map_err(|_| WSError::OidcError("Failed to set path".to_string()))?;

        // Send request
        let future_response = outgoing_handler::handle(request, None)
            .map_err(|_| WSError::OidcError("Failed to send HTTP request".to_string()))?;

        // Wait for response
        let incoming_response = future_response
            .get()
            .ok_or_else(|| WSError::OidcError("HTTP request not ready".to_string()))?
            .map_err(|_| WSError::OidcError("Failed to get HTTP response".to_string()))??;

        // Read response body
        let body = incoming_response
            .consume()
            .map_err(|_| WSError::OidcError("Failed to get response body".to_string()))?;

        let mut bytes = Vec::new();
        let stream = body
            .stream()
            .map_err(|_| WSError::OidcError("Failed to get body stream".to_string()))?;

        loop {
            let chunk = stream
                .blocking_read(8192)
                .map_err(|_| WSError::OidcError("Failed to read from stream".to_string()))?;

            if chunk.is_empty() {
                break;
            }
            bytes.extend_from_slice(&chunk);
        }

        // Parse JSON response
        let json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| WSError::OidcError(format!("Failed to parse GitHub OIDC response: {}", e)))?;

        // Extract the token value
        json.get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                WSError::OidcError("No 'value' field in GitHub OIDC response".to_string())
            })
    }
}

/// Google Cloud OIDC provider
///
/// This is a stub implementation. Full support will be added in a future version.
#[derive(Debug, Clone)]
pub struct GoogleOidcProvider {
    /// Service account credentials path from GOOGLE_APPLICATION_CREDENTIALS env
    _credentials_path: Option<String>,
}

impl GoogleOidcProvider {
    /// Create a new Google OIDC provider
    pub fn new() -> Result<Self, WSError> {
        Self::from_env()
    }

    /// Create a Google OIDC provider from environment variables
    pub fn from_env() -> Result<Self, WSError> {
        let credentials_path = env::var("GOOGLE_APPLICATION_CREDENTIALS").ok();
        Ok(Self {
            _credentials_path: credentials_path,
        })
    }
}

impl OidcProvider for GoogleOidcProvider {
    fn get_token(&self) -> Result<OidcToken, WSError> {
        // TODO: Implement Google Cloud OIDC token retrieval
        Err(WSError::OidcError(
            "Google Cloud OIDC provider not yet implemented".to_string(),
        ))
    }

    fn name(&self) -> &str {
        "Google Cloud"
    }
}

/// GitLab CI OIDC provider
///
/// This is a stub implementation. Full support will be added in a future version.
#[derive(Debug, Clone)]
pub struct GitLabOidcProvider {
    /// CI job token from CI_JOB_JWT env
    _job_jwt: Option<String>,
}

impl GitLabOidcProvider {
    /// Create a new GitLab OIDC provider
    pub fn new() -> Result<Self, WSError> {
        Self::from_env()
    }

    /// Create a GitLab OIDC provider from environment variables
    pub fn from_env() -> Result<Self, WSError> {
        let job_jwt = env::var("CI_JOB_JWT").ok();
        Ok(Self { _job_jwt: job_jwt })
    }
}

impl OidcProvider for GitLabOidcProvider {
    fn get_token(&self) -> Result<OidcToken, WSError> {
        // TODO: Implement GitLab CI OIDC token retrieval
        Err(WSError::OidcError(
            "GitLab CI OIDC provider not yet implemented".to_string(),
        ))
    }

    fn name(&self) -> &str {
        "GitLab CI"
    }
}

/// Auto-detect OIDC provider from environment variables
///
/// Checks for known CI/CD environment variables and returns the appropriate
/// OIDC provider implementation.
///
/// # Detection Order
/// 1. GitHub Actions - checks for `GITHUB_ACTIONS=true`
/// 2. Google Cloud - checks for `GOOGLE_APPLICATION_CREDENTIALS` env var
/// 3. GitLab CI - checks for `GITLAB_CI=true`
///
/// # Returns
/// - `Ok(provider)` if a provider is detected
/// - `Err(WSError::NoOidcProvider)` if no provider is detected
pub fn detect_oidc_provider() -> Result<Box<dyn OidcProvider>, WSError> {
    // Check for GitHub Actions
    if env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true") {
        let provider = GitHubOidcProvider::new()?;
        return Ok(Box::new(provider));
    }

    // Check for Google Cloud
    if env::var("GOOGLE_APPLICATION_CREDENTIALS").is_ok() {
        let provider = GoogleOidcProvider::new()?;
        return Ok(Box::new(provider));
    }

    // Check for GitLab CI
    if env::var("GITLAB_CI").ok().as_deref() == Some("true") {
        let provider = GitLabOidcProvider::new()?;
        return Ok(Box::new(provider));
    }

    // No provider detected
    Err(WSError::NoOidcProvider)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests don't manipulate env vars to avoid unsafe code.
    // Instead, they test the logic with the current environment state.

    #[test]
    fn test_provider_names() {
        // Test that provider names are correct
        let google = GoogleOidcProvider {
            _credentials_path: None,
        };
        assert_eq!(google.name(), "Google Cloud");

        let gitlab = GitLabOidcProvider { _job_jwt: None };
        assert_eq!(gitlab.name(), "GitLab CI");
    }

    #[test]
    fn test_parse_jwt_identity() {
        // Sample JWT token (header.payload.signature)
        // Payload: {"email":"test@example.com","sub":"user123","iss":"https://token.actions.githubusercontent.com"}
        let payload = r#"{"email":"test@example.com","sub":"user123","iss":"https://token.actions.githubusercontent.com"}"#;
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
        let token = format!("header.{}.signature", encoded_payload);

        let identity = GitHubOidcProvider::parse_identity(&token).unwrap();
        assert_eq!(identity, "test@example.com");
    }

    #[test]
    fn test_parse_jwt_identity_no_email() {
        // Sample JWT token with only 'sub' field
        let payload = r#"{"sub":"user123","iss":"https://token.actions.githubusercontent.com"}"#;
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
        let token = format!("header.{}.signature", encoded_payload);

        let identity = GitHubOidcProvider::parse_identity(&token).unwrap();
        assert_eq!(identity, "user123");
    }

    #[test]
    fn test_parse_jwt_issuer() {
        let payload = r#"{"email":"test@example.com","iss":"https://token.actions.githubusercontent.com"}"#;
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload);
        let token = format!("header.{}.signature", encoded_payload);

        let issuer = GitHubOidcProvider::parse_issuer(&token).unwrap();
        assert_eq!(issuer, "https://token.actions.githubusercontent.com");
    }

    #[test]
    fn test_parse_invalid_jwt() {
        let result = GitHubOidcProvider::parse_identity("invalid-token");
        assert!(matches!(result, Err(WSError::OidcError(_))));
    }

    #[test]
    fn test_google_provider_not_implemented() {
        let provider = GoogleOidcProvider::new().unwrap();
        let result = provider.get_token();
        assert!(matches!(result, Err(WSError::OidcError(_))));
    }

    #[test]
    fn test_gitlab_provider_not_implemented() {
        let provider = GitLabOidcProvider::new().unwrap();
        let result = provider.get_token();
        assert!(matches!(result, Err(WSError::OidcError(_))));
    }

    #[test]
    fn test_oidc_token_serialization() {
        let token = OidcToken {
            token: "test-token".to_string(),
            identity: "user@example.com".to_string(),
            issuer: "https://issuer.example.com".to_string(),
        };

        let json = serde_json::to_string(&token).unwrap();
        let deserialized: OidcToken = serde_json::from_str(&json).unwrap();

        assert_eq!(token.token, deserialized.token);
        assert_eq!(token.identity, deserialized.identity);
        assert_eq!(token.issuer, deserialized.issuer);
    }
}
