/// The WasmSign2 error type.
#[derive(Debug, thiserror::Error)]
pub enum WSError {
    #[error("Internal error: [{0}]")]
    InternalError(String),

    #[error("Parse error")]
    ParseError,

    #[error("I/O error")]
    IOError(#[from] std::io::Error),

    #[error("EOF")]
    Eof,

    #[error("UTF-8 error")]
    UTF8Error(#[from] std::str::Utf8Error),

    #[error("Ed25519 signature function error")]
    CryptoError(#[from] ed25519_compact::Error),

    #[error("Unsupported module type")]
    UnsupportedModuleType,

    #[error("No valid signatures")]
    VerificationFailed,

    #[error("No valid signatures for the given predicates")]
    VerificationFailedForPredicates,

    #[error("No signatures found")]
    NoSignatures,

    #[error("Unsupported key type")]
    UnsupportedKeyType,

    #[error("Invalid argument")]
    InvalidArgument,

    #[error("Incompatible signature version")]
    IncompatibleSignatureVersion,

    #[error("Duplicate signature")]
    DuplicateSignature,

    #[error("Sections can only be verified between pre-defined boundaries")]
    InvalidVerificationPredicate,

    #[error("Signature already attached")]
    SignatureAlreadyAttached,

    #[error("Duplicate public key")]
    DuplicatePublicKey,

    #[error("Unknown public key")]
    UnknownPublicKey,

    #[error("Too many hashes (max: {0})")]
    TooManyHashes(usize),

    #[error("Too many signatures (max: {0})")]
    TooManySignatures(usize),

    #[error("Too many certificates (max: {0})")]
    TooManyCertificates(usize),

    #[error("Usage error: {0}")]
    UsageError(&'static str),

    #[error("OIDC error: {0}")]
    OidcError(String),

    #[error("Fulcio error: {0}")]
    FulcioError(String),

    #[error("Rekor error: {0}")]
    RekorError(String),

    #[error("Certificate verification failed: {0}")]
    CertificateError(String),

    #[error("Certificate pinning failed: {0}")]
    CertificatePinningError(String),

    #[error("Keyless signature format error: {0}")]
    KeylessFormatError(String),

    #[error("No OIDC provider detected")]
    NoOidcProvider,

    #[error("X509 error: {0}")]
    X509Error(String),

    // Hardware security errors
    #[error("Hardware error: {0}")]
    HardwareError(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Invalid key handle")]
    InvalidKeyHandle,

    #[error("No space available in hardware key storage")]
    NoSpace,

    // Certificate provisioning errors
    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    // Time validation errors
    #[error("Time error: {0}")]
    TimeError(String),

    // Transformation chain verification errors
    #[error("Chain verification failed: {0}")]
    ChainVerificationFailed(String),

    #[error("Missing transformation attestation")]
    MissingAttestation,

    #[error("Untrusted transformation tool: {0}")]
    UntrustedTool(String),

    #[error("Untrusted attestation signer: {0}")]
    UntrustedAttestationSigner(String),

    #[error("Missing root signature: expected signed input at '{0}'")]
    MissingRootSignature(String),

    #[error("Chain gap: no attestation links '{from}' to '{to}'")]
    ChainGap { from: String, to: String },

    #[error("Invalid attestation signature: {0}")]
    InvalidAttestationSignature(String),

    #[error("Attestation timestamp invalid: {0}")]
    AttestationTimestampInvalid(String),
}

// X509 error conversion
impl From<x509_parser::error::X509Error> for WSError {
    fn from(err: x509_parser::error::X509Error) -> Self {
        WSError::X509Error(format!("{:?}", err))
    }
}

// WASI HTTP error conversion for wasm32-wasip2 target
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
impl From<wasi::http::types::ErrorCode> for WSError {
    fn from(err: wasi::http::types::ErrorCode) -> Self {
        WSError::InternalError(format!("WASI HTTP error: {:?}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        // Test basic error messages
        let err = WSError::ParseError;
        assert_eq!(err.to_string(), "Parse error");

        let err = WSError::Eof;
        assert_eq!(err.to_string(), "EOF");

        let err = WSError::UnsupportedModuleType;
        assert_eq!(err.to_string(), "Unsupported module type");

        let err = WSError::VerificationFailed;
        assert_eq!(err.to_string(), "No valid signatures");

        let err = WSError::NoSignatures;
        assert_eq!(err.to_string(), "No signatures found");

        let err = WSError::UnsupportedKeyType;
        assert_eq!(err.to_string(), "Unsupported key type");

        let err = WSError::InvalidArgument;
        assert_eq!(err.to_string(), "Invalid argument");

        let err = WSError::IncompatibleSignatureVersion;
        assert_eq!(err.to_string(), "Incompatible signature version");

        let err = WSError::DuplicateSignature;
        assert_eq!(err.to_string(), "Duplicate signature");

        let err = WSError::InvalidVerificationPredicate;
        assert_eq!(
            err.to_string(),
            "Sections can only be verified between pre-defined boundaries"
        );

        let err = WSError::SignatureAlreadyAttached;
        assert_eq!(err.to_string(), "Signature already attached");

        let err = WSError::DuplicatePublicKey;
        assert_eq!(err.to_string(), "Duplicate public key");

        let err = WSError::UnknownPublicKey;
        assert_eq!(err.to_string(), "Unknown public key");
    }

    #[test]
    fn test_error_with_params() {
        let err = WSError::InternalError("test error".to_string());
        assert_eq!(err.to_string(), "Internal error: [test error]");

        let err = WSError::TooManyHashes(100);
        assert_eq!(err.to_string(), "Too many hashes (max: 100)");

        let err = WSError::TooManySignatures(50);
        assert_eq!(err.to_string(), "Too many signatures (max: 50)");

        let err = WSError::UsageError("invalid usage");
        assert_eq!(err.to_string(), "Usage error: invalid usage");

        let err = WSError::VerificationFailedForPredicates;
        assert_eq!(
            err.to_string(),
            "No valid signatures for the given predicates"
        );
    }

    #[test]
    fn test_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: WSError = io_err.into();
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_error_from_utf8_error() {
        let invalid_utf8 = vec![0, 159, 146, 150];
        let utf8_err = std::str::from_utf8(&invalid_utf8).unwrap_err();
        let err: WSError = utf8_err.into();
        assert!(err.to_string().contains("UTF-8 error"));
    }

    #[test]
    fn test_error_debug() {
        // Verify Debug trait works
        let err = WSError::ParseError;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("ParseError"));
    }
}
