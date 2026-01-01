//! Secure file operations with restrictive permissions
//!
//! This module provides utilities for securely reading and writing sensitive files
//! such as private keys and tokens. On Unix systems, it enforces restrictive
//! permissions (0600 = owner read/write only) to prevent credential theft.
//!
//! # Security Features
//!
//! - Creates files with mode 0600 (owner read/write only) on Unix
//! - Warns when reading files with overly permissive permissions
//! - Cross-platform support with graceful fallback on non-Unix systems
//!
//! # Example
//!
//! ```no_run
//! use wsc::secure_file;
//! use std::path::Path;
//!
//! // Write sensitive data securely
//! secure_file::write_secure(Path::new("/path/to/secret.key"), b"secret data")?;
//!
//! // Read with permission checking
//! let data = secure_file::read_secure(Path::new("/path/to/secret.key"))?;
//! # Ok::<(), wsc::WSError>(())
//! ```

use crate::error::WSError;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// The restrictive permission mode for sensitive files (owner read/write only)
#[cfg(unix)]
pub const SECURE_FILE_MODE: u32 = 0o600;

/// Check if file permissions are secure (Unix only)
///
/// Returns `Ok(())` if permissions are secure (0600 or more restrictive),
/// or logs a warning and returns `Ok(())` if permissions are too permissive.
///
/// On non-Unix platforms, this always returns `Ok(())` with a debug log.
#[cfg(unix)]
pub fn check_permissions(path: &Path) -> Result<(), WSError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();

    // Check if group or others have any access (bits 0o077)
    // mode & 0o777 gives us the permission bits (ignoring file type bits)
    let perm_bits = mode & 0o777;

    if perm_bits & 0o077 != 0 {
        // File is world or group readable/writable/executable
        log::warn!(
            "SECURITY WARNING: File '{}' has overly permissive permissions (mode {:o}). \
             Sensitive files should have mode 0600 (owner read/write only). \
             Consider running: chmod 600 '{}'",
            path.display(),
            perm_bits,
            path.display()
        );
    }

    Ok(())
}

#[cfg(not(unix))]
pub fn check_permissions(path: &Path) -> Result<(), WSError> {
    log::debug!(
        "Permission check skipped for '{}': not supported on this platform. \
         On Windows, ensure proper ACLs are set for sensitive files.",
        path.display()
    );
    Ok(())
}

/// Set secure permissions on a file (Unix only)
///
/// Sets the file permissions to 0600 (owner read/write only).
/// On non-Unix platforms, this logs a warning and succeeds.
#[cfg(unix)]
pub fn set_secure_permissions(path: &Path) -> Result<(), WSError> {
    use std::os::unix::fs::PermissionsExt;

    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(SECURE_FILE_MODE);
    fs::set_permissions(path, perms)?;

    Ok(())
}

#[cfg(not(unix))]
pub fn set_secure_permissions(path: &Path) -> Result<(), WSError> {
    log::warn!(
        "Cannot set restrictive file permissions for '{}': not supported on this platform. \
         Ensure proper access controls are configured for sensitive files.",
        path.display()
    );
    Ok(())
}

/// Create a file with secure permissions from the start (Unix only)
///
/// On Unix, this creates the file with mode 0600 before any data is written,
/// preventing race conditions where the file is briefly accessible.
///
/// On non-Unix platforms, this creates the file normally and logs a warning.
#[cfg(unix)]
pub fn create_secure_file(path: &Path) -> Result<File, WSError> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(SECURE_FILE_MODE)
        .open(path)?;

    Ok(file)
}

#[cfg(not(unix))]
pub fn create_secure_file(path: &Path) -> Result<File, WSError> {
    log::warn!(
        "Creating file '{}' without restrictive permissions: not supported on this platform. \
         Ensure proper access controls are configured for sensitive files.",
        path.display()
    );

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;

    Ok(file)
}

/// Write data to a file with secure permissions
///
/// This function:
/// 1. Creates the file with mode 0600 (Unix) to prevent race conditions
/// 2. Writes the data
/// 3. Verifies the permissions are correct
///
/// # Security
///
/// On Unix systems, the file is created with restrictive permissions from the start,
/// so there's no window where the file exists with permissive permissions.
///
/// On non-Unix systems, the file is created normally with a warning logged.
pub fn write_secure(path: &Path, data: &[u8]) -> Result<(), WSError> {
    let mut file = create_secure_file(path)?;
    file.write_all(data)?;
    file.sync_all()?;

    // Double-check permissions on Unix (defense in depth)
    #[cfg(unix)]
    {
        set_secure_permissions(path)?;
    }

    Ok(())
}

/// Write a string to a file with secure permissions
///
/// See [`write_secure`] for details on the security guarantees.
pub fn write_secure_string(path: &Path, content: &str) -> Result<(), WSError> {
    write_secure(path, content.as_bytes())
}

/// Read a file and check its permissions
///
/// This function:
/// 1. Checks if the file has secure permissions (Unix only)
/// 2. Logs a warning if permissions are too permissive
/// 3. Reads and returns the file contents
///
/// # Security
///
/// This function will still read the file even if permissions are too permissive,
/// but it will log a warning to alert the user to the security issue.
pub fn read_secure(path: &Path) -> Result<Vec<u8>, WSError> {
    // Check permissions first
    check_permissions(path)?;

    // Read the file
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    Ok(contents)
}

/// Read a file as a string and check its permissions
///
/// See [`read_secure`] for details on the security guarantees.
pub fn read_secure_string(path: &Path) -> Result<String, WSError> {
    let contents = read_secure(path)?;
    String::from_utf8(contents).map_err(|e| {
        WSError::InternalError(format!("Invalid UTF-8 in secure file: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_path(name: &str) -> std::path::PathBuf {
        env::temp_dir().join(format!("wsc_test_secure_file_{}", name))
    }

    #[test]
    fn test_write_and_read_secure() {
        let path = temp_path("write_read.key");
        let data = b"test secret data";

        // Write securely
        write_secure(&path, data).unwrap();

        // Read back
        let read_data = read_secure(&path).unwrap();
        assert_eq!(read_data, data);

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_write_and_read_secure_string() {
        let path = temp_path("write_read_str.key");
        let content = "test secret string content";

        // Write securely
        write_secure_string(&path, content).unwrap();

        // Read back
        let read_content = read_secure_string(&path).unwrap();
        assert_eq!(read_content, content);

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_secure_permissions_set_correctly() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("perms.key");
        let data = b"test data";

        // Write securely
        write_secure(&path, data).unwrap();

        // Check permissions
        let metadata = fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, SECURE_FILE_MODE, "File should have mode 0600");

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_check_permissions_secure() {
        let path = temp_path("check_secure.key");

        // Create file with secure permissions
        write_secure(&path, b"test").unwrap();

        // Should pass without warning (we can't easily capture the log)
        let result = check_permissions(&path);
        assert!(result.is_ok());

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_check_permissions_insecure_logs_warning() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("check_insecure.key");

        // Create file with insecure permissions
        fs::write(&path, b"test").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644); // world-readable
        fs::set_permissions(&path, perms).unwrap();

        // Should succeed but would log a warning
        let result = check_permissions(&path);
        assert!(result.is_ok());

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_set_secure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("set_perms.key");

        // Create file with default (insecure) permissions
        fs::write(&path, b"test").unwrap();

        // Set secure permissions
        set_secure_permissions(&path).unwrap();

        // Verify
        let metadata = fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, SECURE_FILE_MODE);

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_create_secure_file() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("create_secure.key");

        // Create secure file
        let mut file = create_secure_file(&path).unwrap();
        file.write_all(b"test data").unwrap();
        drop(file);

        // Check permissions were set correctly from the start
        let metadata = fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, SECURE_FILE_MODE);

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_write_secure_creates_parent_dirs_not() {
        // Note: write_secure doesn't create parent directories
        // This is intentional - the caller should create the directory structure
        let path = temp_path("nonexistent_dir/file.key");

        let result = write_secure(&path, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_read_secure_nonexistent_file() {
        let path = temp_path("nonexistent.key");

        let result = read_secure(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_file() {
        let path = temp_path("empty.key");

        // Write empty data
        write_secure(&path, b"").unwrap();

        // Read back
        let read_data = read_secure(&path).unwrap();
        assert!(read_data.is_empty());

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_large_file() {
        let path = temp_path("large.key");

        // Write 1MB of data
        let data: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
        write_secure(&path, &data).unwrap();

        // Read back
        let read_data = read_secure(&path).unwrap();
        assert_eq!(read_data, data);

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_overwrite_existing_file() {
        let path = temp_path("overwrite.key");

        // Write initial data
        write_secure(&path, b"initial data").unwrap();

        // Overwrite with new data
        write_secure(&path, b"new data").unwrap();

        // Read back
        let read_data = read_secure(&path).unwrap();
        assert_eq!(read_data, b"new data");

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_overwrite_preserves_secure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("overwrite_perms.key");

        // Write initial data
        write_secure(&path, b"initial").unwrap();

        // Verify initial permissions
        let mode1 = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode1, SECURE_FILE_MODE);

        // Overwrite
        write_secure(&path, b"new data").unwrap();

        // Verify permissions still secure
        let mode2 = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode2, SECURE_FILE_MODE);

        // Cleanup
        fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_read_insecure_file_still_reads() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("read_insecure.key");

        // Create file with insecure permissions
        fs::write(&path, b"secret data").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o777); // world-readable/writable/executable
        fs::set_permissions(&path, perms).unwrap();

        // Should still read the file (with warning logged)
        let result = read_secure(&path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"secret data");

        // Cleanup
        fs::remove_file(&path).ok();
    }
}
