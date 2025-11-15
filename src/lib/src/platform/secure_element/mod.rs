/// Secure Element integration for embedded systems
///
/// This module provides support for hardware secure elements commonly used in
/// IoT and embedded systems:
///
/// - **ATECC608**: Microchip CryptoAuthentication (I2C, cost-effective)
/// - **SE050**: NXP EdgeLock (I2C/SPI, advanced features)
/// - **OPTIGA**: Infineon Trust M (I2C, automotive-grade)
///
/// # Security Features
///
/// Secure elements provide:
/// - Hardware key generation with true RNG
/// - Keys stored in tamper-resistant storage
/// - Cryptographic operations in hardware
/// - No key material exposed to host CPU
/// - Physical security (some chips are FIPS 140-2 certified)
///
/// # Communication
///
/// Most secure elements use I2C or SPI protocols:
/// - **I2C**: Most common, 100-400 kHz
/// - **SPI**: Higher speed, less common
/// - **UART**: Rare, legacy devices
///
/// # Architecture
///
/// ```text
/// Application
///     ↓
/// SecureElementProvider (trait)
///     ↓
/// Platform-specific driver (I2C/SPI)
///     ↓
/// Secure Element Hardware
/// ```
///
/// # Key Slots
///
/// Secure elements organize keys in "slots":
/// - Fixed number of slots (typically 16)
/// - Each slot has configuration (usage policy)
/// - Keys can be locked (write-once, read-never)
/// - Slot can require authentication
///
/// # Example
///
/// ```ignore
/// use wsc::platform::secure_element::{Atecc608Provider, KeySlot};
///
/// // Initialize secure element on I2C bus 1, address 0x60
/// let se = Atecc608Provider::new("/dev/i2c-1", 0x60)?;
///
/// // Generate key in slot 0 (locked, never extractable)
/// let handle = se.generate_in_slot(KeySlot(0), true)?;
///
/// // Sign data (operation happens IN secure element)
/// let signature = se.sign(handle, data)?;
///
/// // Public key can be exported
/// let public_key = se.get_public_key(handle)?;
/// ```
use crate::error::WSError;
use crate::platform::{Attestation, KeyHandle, SecureKeyProvider, SecurityLevel};
use crate::signature::PublicKey;

#[cfg(feature = "atecc608")]
pub mod atecc608;

#[cfg(feature = "se050")]
pub mod se050;

/// Secure element key slot identifier
///
/// Secure elements organize keys in numbered slots.
/// Each chip has a fixed number of slots (typically 16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeySlot(pub u8);

impl KeySlot {
    /// Maximum slot number for most secure elements
    pub const MAX: u8 = 15;

    /// Validate slot number is in valid range
    pub fn validate(&self) -> Result<(), WSError> {
        if self.0 > Self::MAX {
            return Err(WSError::InvalidArgument);
        }
        Ok(())
    }
}

/// Configuration for a key slot
#[derive(Debug, Clone)]
pub struct SlotConfig {
    /// Slot number
    pub slot: KeySlot,
    /// Is the key locked (write-once, never extractable)?
    pub locked: bool,
    /// Require authentication for key usage?
    pub requires_auth: bool,
    /// Key usage policy (signing, encryption, etc.)
    pub usage: KeyUsage,
}

/// Key usage policies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    /// Key can be used for signing only
    Signing,
    /// Key can be used for ECDH key agreement
    KeyAgreement,
    /// Key can be used for both signing and key agreement
    General,
}

/// I2C bus interface abstraction
///
/// This trait allows different I2C implementations (linux-embedded-hal,
/// platform-specific drivers, or mocks for testing).
pub trait I2cBus: Send + Sync {
    /// Write data to device at address
    fn write(&mut self, address: u8, data: &[u8]) -> Result<(), WSError>;

    /// Read data from device at address
    fn read(&mut self, address: u8, buffer: &mut [u8]) -> Result<(), WSError>;

    /// Write then read (common pattern for secure elements)
    fn write_read(
        &mut self,
        address: u8,
        write_data: &[u8],
        read_buffer: &mut [u8],
    ) -> Result<(), WSError>;
}

/// Unified secure element provider
///
/// This is a high-level interface that abstracts over different secure
/// element types. For most use cases, use this instead of chip-specific
/// implementations.
pub struct SecureElementProvider {
    inner: Box<dyn SecureKeyProvider>,
    chip_type: ChipType,
}

/// Supported secure element chips
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipType {
    /// Microchip ATECC608 series
    Atecc608,
    /// NXP SE050 EdgeLock
    Se050,
    /// Infineon OPTIGA Trust M
    OptigaTrustM,
}

impl SecureElementProvider {
    /// Auto-detect secure element on I2C bus
    ///
    /// Probes common I2C addresses for known secure elements.
    ///
    /// # Arguments
    ///
    /// * `bus_path` - I2C bus device path (e.g., "/dev/i2c-1")
    ///
    /// # Returns
    ///
    /// Detected secure element provider, or error if none found
    pub fn auto_detect(_bus_path: &str) -> Result<Self, WSError> {
        // Try common addresses in order of likelihood
        // ATECC608: 0x60 (most common in IoT)
        // SE050: 0x48 (NXP default)
        // OPTIGA: 0x30 (Infineon default)

        #[cfg(feature = "atecc608")]
        {
            // Try ATECC608 first (most common)
            if let Ok(provider) = atecc608::Atecc608Provider::new(_bus_path, 0x60) {
                return Ok(SecureElementProvider {
                    inner: Box::new(provider),
                    chip_type: ChipType::Atecc608,
                });
            }
        }

        // TODO(se050): Add SE050 detection when implemented
        // #[cfg(feature = "se050")]
        // {
        //     if let Ok(provider) = se050::Se050Provider::new(_bus_path, 0x48) {
        //         return Ok(SecureElementProvider {
        //             inner: Box::new(provider),
        //             chip_type: ChipType::Se050,
        //         });
        //     }
        // }

        Err(WSError::HardwareError(
            "No secure element detected on I2C bus".to_string(),
        ))
    }

    /// Get the detected chip type
    pub fn chip_type(&self) -> ChipType {
        self.chip_type
    }
}

// Forward trait implementation to inner provider
impl SecureKeyProvider for SecureElementProvider {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn security_level(&self) -> SecurityLevel {
        self.inner.security_level()
    }

    fn health_check(&self) -> Result<(), WSError> {
        self.inner.health_check()
    }

    fn generate_key(&self) -> Result<KeyHandle, WSError> {
        self.inner.generate_key()
    }

    fn load_key(&self, key_id: &str) -> Result<KeyHandle, WSError> {
        self.inner.load_key(key_id)
    }

    fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, WSError> {
        self.inner.sign(handle, data)
    }

    fn get_public_key(&self, handle: KeyHandle) -> Result<PublicKey, WSError> {
        self.inner.get_public_key(handle)
    }

    fn attestation(&self, handle: KeyHandle) -> Result<Option<Attestation>, WSError> {
        self.inner.attestation(handle)
    }

    fn delete_key(&self, handle: KeyHandle) -> Result<(), WSError> {
        self.inner.delete_key(handle)
    }

    fn list_keys(&self) -> Result<Vec<KeyHandle>, WSError> {
        self.inner.list_keys()
    }
}

/// Mock I2C bus for testing
///
/// This allows testing secure element code without real hardware.
#[cfg(test)]
pub struct MockI2cBus {
    /// Simulated device responses
    responses: std::collections::HashMap<Vec<u8>, Vec<u8>>,
}

#[cfg(test)]
impl MockI2cBus {
    pub fn new() -> Self {
        MockI2cBus {
            responses: std::collections::HashMap::new(),
        }
    }

    pub fn add_response(&mut self, command: Vec<u8>, response: Vec<u8>) {
        self.responses.insert(command, response);
    }
}

#[cfg(test)]
impl I2cBus for MockI2cBus {
    fn write(&mut self, _address: u8, _data: &[u8]) -> Result<(), WSError> {
        Ok(())
    }

    fn read(&mut self, _address: u8, buffer: &mut [u8]) -> Result<(), WSError> {
        // Return zeros for mock
        buffer.fill(0);
        Ok(())
    }

    fn write_read(
        &mut self,
        _address: u8,
        write_data: &[u8],
        read_buffer: &mut [u8],
    ) -> Result<(), WSError> {
        if let Some(response) = self.responses.get(write_data) {
            let copy_len = response.len().min(read_buffer.len());
            read_buffer[..copy_len].copy_from_slice(&response[..copy_len]);
            Ok(())
        } else {
            read_buffer.fill(0);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_slot_validation() {
        assert!(KeySlot(0).validate().is_ok());
        assert!(KeySlot(15).validate().is_ok());
        assert!(KeySlot(16).validate().is_err()); // Out of range
        assert!(KeySlot(255).validate().is_err());
    }

    #[test]
    fn test_key_slot_max() {
        assert_eq!(KeySlot::MAX, 15);
    }

    #[test]
    fn test_slot_config_creation() {
        let config = SlotConfig {
            slot: KeySlot(0),
            locked: true,
            requires_auth: false,
            usage: KeyUsage::Signing,
        };

        assert_eq!(config.slot.0, 0);
        assert!(config.locked);
        assert!(!config.requires_auth);
        assert_eq!(config.usage, KeyUsage::Signing);
    }

    #[test]
    fn test_mock_i2c_bus() {
        let mut bus = MockI2cBus::new();

        // Add a response
        let command = vec![0x01, 0x02, 0x03];
        let response = vec![0x04, 0x05, 0x06];
        bus.add_response(command.clone(), response.clone());

        // Test write_read
        let mut read_buffer = vec![0u8; 3];
        assert!(bus.write_read(0x60, &command, &mut read_buffer).is_ok());
        assert_eq!(read_buffer, response);
    }

    #[test]
    fn test_chip_type_equality() {
        assert_eq!(ChipType::Atecc608, ChipType::Atecc608);
        assert_ne!(ChipType::Atecc608, ChipType::Se050);
    }

    #[test]
    fn test_key_usage() {
        let signing = KeyUsage::Signing;
        let agreement = KeyUsage::KeyAgreement;
        let general = KeyUsage::General;

        assert_eq!(signing, KeyUsage::Signing);
        assert_ne!(signing, agreement);
        assert_ne!(agreement, general);
    }
}
