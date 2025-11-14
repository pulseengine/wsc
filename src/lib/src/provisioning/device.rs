/// Device identity management
///
/// This module provides device identity abstraction for certificate provisioning.
/// Each IoT device has a unique identifier that's embedded in its certificate.

use crate::error::WSError;
use std::fmt;

/// Unique device identifier
///
/// Device IDs are typically:
/// - MAC addresses (e.g., "00:1A:2B:3C:4D:5E")
/// - Serial numbers (e.g., "SN-2024-001234")
/// - UUIDs (e.g., "550e8400-e29b-41d4-a716-446655440000")
/// - Custom format (e.g., "factory-A-line-3-device-42")
///
/// # Security
///
/// Device IDs should be:
/// - Unique per device
/// - Stable (never changes)
/// - Not easily guessable
/// - Recorded in manufacturing database
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceIdentity {
    /// The unique device identifier
    id: String,
    /// Optional device type/model
    device_type: Option<String>,
    /// Optional hardware revision
    hardware_revision: Option<String>,
    /// Optional firmware version at provisioning time
    firmware_version: Option<String>,
}

impl DeviceIdentity {
    /// Create a new device identity
    ///
    /// # Arguments
    ///
    /// * `id` - Unique device identifier
    ///
    /// # Example
    ///
    /// ```ignore
    /// let device = DeviceIdentity::new("device-12345");
    /// ```
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            device_type: None,
            hardware_revision: None,
            firmware_version: None,
        }
    }

    /// Create device identity from MAC address
    ///
    /// # Arguments
    ///
    /// * `mac` - MAC address bytes (6 bytes)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let device = DeviceIdentity::from_mac(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
    /// ```
    pub fn from_mac(mac: &[u8]) -> Result<Self, WSError> {
        if mac.len() != 6 {
            return Err(WSError::InvalidArgument);
        }

        let mac_str = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        Ok(Self::new(mac_str))
    }

    /// Create device identity from UUID bytes
    ///
    /// # Arguments
    ///
    /// * `uuid` - UUID bytes (16 bytes)
    pub fn from_uuid(uuid: &[u8]) -> Result<Self, WSError> {
        if uuid.len() != 16 {
            return Err(WSError::InvalidArgument);
        }

        let uuid_str = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            uuid[0], uuid[1], uuid[2], uuid[3],
            uuid[4], uuid[5],
            uuid[6], uuid[7],
            uuid[8], uuid[9],
            uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
        );

        Ok(Self::new(uuid_str))
    }

    /// Get the device ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Set device type/model
    pub fn with_device_type(mut self, device_type: impl Into<String>) -> Self {
        self.device_type = Some(device_type.into());
        self
    }

    /// Set hardware revision
    pub fn with_hardware_revision(mut self, revision: impl Into<String>) -> Self {
        self.hardware_revision = Some(revision.into());
        self
    }

    /// Set firmware version
    pub fn with_firmware_version(mut self, version: impl Into<String>) -> Self {
        self.firmware_version = Some(version.into());
        self
    }

    /// Get device type
    pub fn device_type(&self) -> Option<&str> {
        self.device_type.as_deref()
    }

    /// Get hardware revision
    pub fn hardware_revision(&self) -> Option<&str> {
        self.hardware_revision.as_deref()
    }

    /// Get firmware version
    pub fn firmware_version(&self) -> Option<&str> {
        self.firmware_version.as_deref()
    }

    /// Validate device ID format
    ///
    /// Checks that device ID:
    /// - Is not empty
    /// - Is not too long (max 64 chars)
    /// - Contains only safe characters (alphanumeric, dash, underscore, colon)
    pub fn validate(&self) -> Result<(), WSError> {
        if self.id.is_empty() {
            return Err(WSError::InvalidArgument);
        }

        if self.id.len() > 64 {
            return Err(WSError::InvalidArgument);
        }

        // Check for safe characters only
        let is_safe = self.id.chars().all(|c| {
            c.is_alphanumeric() || c == '-' || c == '_' || c == ':' || c == '.'
        });

        if !is_safe {
            return Err(WSError::InvalidArgument);
        }

        Ok(())
    }

    /// Create Common Name (CN) for certificate Subject
    ///
    /// Format: "Device {id}"
    pub fn to_common_name(&self) -> String {
        format!("Device {}", self.id)
    }

    /// Create a description string with all metadata
    pub fn to_description(&self) -> String {
        let mut desc = format!("Device ID: {}", self.id);

        if let Some(device_type) = &self.device_type {
            desc.push_str(&format!(", Type: {}", device_type));
        }

        if let Some(hw_rev) = &self.hardware_revision {
            desc.push_str(&format!(", HW Rev: {}", hw_rev));
        }

        if let Some(fw_ver) = &self.firmware_version {
            desc.push_str(&format!(", FW Ver: {}", fw_ver));
        }

        desc
    }
}

impl fmt::Display for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_identity_creation() {
        let device = DeviceIdentity::new("device-123");
        assert_eq!(device.id(), "device-123");
        assert_eq!(device.to_string(), "device-123");
    }

    #[test]
    fn test_device_identity_with_metadata() {
        let device = DeviceIdentity::new("device-123")
            .with_device_type("TemperatureSensor")
            .with_hardware_revision("1.2")
            .with_firmware_version("2.0.1");

        assert_eq!(device.id(), "device-123");
        assert_eq!(device.device_type(), Some("TemperatureSensor"));
        assert_eq!(device.hardware_revision(), Some("1.2"));
        assert_eq!(device.firmware_version(), Some("2.0.1"));
    }

    #[test]
    fn test_from_mac() {
        let mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let device = DeviceIdentity::from_mac(&mac).unwrap();
        assert_eq!(device.id(), "00:1A:2B:3C:4D:5E");
    }

    #[test]
    fn test_from_mac_invalid_length() {
        let mac = [0x00, 0x1A, 0x2B]; // Too short
        let result = DeviceIdentity::from_mac(&mac);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_uuid() {
        let uuid = [
            0x55, 0x0e, 0x84, 0x00,
            0xe2, 0x9b,
            0x41, 0xd4,
            0xa7, 0x16,
            0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
        ];
        let device = DeviceIdentity::from_uuid(&uuid).unwrap();
        assert_eq!(device.id(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_from_uuid_invalid_length() {
        let uuid = [0x55, 0x0e, 0x84]; // Too short
        let result = DeviceIdentity::from_uuid(&uuid);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_good_ids() {
        assert!(DeviceIdentity::new("device-123").validate().is_ok());
        assert!(DeviceIdentity::new("SN-2024-001234").validate().is_ok());
        assert!(DeviceIdentity::new("00:1A:2B:3C:4D:5E").validate().is_ok());
        assert!(DeviceIdentity::new("factory_A_line_3").validate().is_ok());
        assert!(DeviceIdentity::new("device.123").validate().is_ok());
    }

    #[test]
    fn test_validate_bad_ids() {
        // Empty
        assert!(DeviceIdentity::new("").validate().is_err());

        // Too long
        let long_id = "a".repeat(65);
        assert!(DeviceIdentity::new(long_id).validate().is_err());

        // Invalid characters
        assert!(DeviceIdentity::new("device@123").validate().is_err());
        assert!(DeviceIdentity::new("device#123").validate().is_err());
        assert!(DeviceIdentity::new("device 123").validate().is_err()); // Space
    }

    #[test]
    fn test_to_common_name() {
        let device = DeviceIdentity::new("device-123");
        assert_eq!(device.to_common_name(), "Device device-123");
    }

    #[test]
    fn test_to_description() {
        let device = DeviceIdentity::new("device-123")
            .with_device_type("Sensor")
            .with_hardware_revision("1.0")
            .with_firmware_version("2.1.0");

        let desc = device.to_description();
        assert!(desc.contains("Device ID: device-123"));
        assert!(desc.contains("Type: Sensor"));
        assert!(desc.contains("HW Rev: 1.0"));
        assert!(desc.contains("FW Ver: 2.1.0"));
    }

    #[test]
    fn test_device_identity_equality() {
        let device1 = DeviceIdentity::new("device-123");
        let device2 = DeviceIdentity::new("device-123");
        let device3 = DeviceIdentity::new("device-456");

        assert_eq!(device1, device2);
        assert_ne!(device1, device3);
    }
}
