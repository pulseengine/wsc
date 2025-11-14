# Embedded Security Implementation Roadmap

**Decision**: Invest in embedded/offline support
**Timeline**: 3-6 months
**Goal**: Production-ready WebAssembly signing for embedded, IoT, and air-gapped systems

---

## 🎯 Success Criteria

### Must Have
- ✅ Hardware-backed key storage (TPM 2.0, Secure Elements)
- ✅ Offline operation (no internet dependency)
- ✅ Pre-provisioned certificate support
- ✅ Keys never exposed in plaintext
- ✅ Secure boot chain integration
- ✅ Cross-platform support (ARM, x86, RISC-V)

### Nice to Have
- ✅ Hardware attestation
- ✅ Secure firmware update workflow
- ✅ Manufacturing provisioning tools
- ✅ Key rotation mechanisms
- ✅ Audit logging

---

## 📅 Phase 1: Foundation (Weeks 1-2)

### Week 1: Critical Security Fixes & Architecture
**Status**: 🚧 In Progress

#### Day 1-2: Immediate Security Fixes
- [x] Fix secret key Debug output exposure
- [x] Implement key zeroization with zeroize crate
- [x] Add cargo-audit, cargo-deny to CI
- [x] Create SECURITY.md

#### Day 3-5: Hardware Abstraction Layer Design
- [ ] Design `SecureKeyProvider` trait
- [ ] Define platform abstraction interfaces
- [ ] Create error types for hardware operations
- [ ] Design key handle management

**Deliverables**:
```rust
// Core abstraction
pub trait SecureKeyProvider {
    fn generate_key(&self) -> Result<KeyHandle, WSError>;
    fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, WSError>;
    fn get_public_key(&self, handle: KeyHandle) -> Result<PublicKey, WSError>;
    fn attestation(&self, handle: KeyHandle) -> Result<Attestation, WSError>;
}

// Unified signing interface
pub enum SigningMode {
    Software(SecretKey),              // Existing: development
    Keyless(OidcToken),               // Existing: cloud/CI
    HardwareBacked(Box<dyn SecureKeyProvider>), // NEW: production embedded
    PreProvisioned(ProvisionedKey),   // NEW: offline/air-gapped
}
```

### Week 2: Software Key Provider Refactor
**Goal**: Refactor existing code to use new abstraction

#### Tasks
- [ ] Implement `SecureKeyProvider` for existing software keys
- [ ] Update `SecretKey::sign()` to use trait
- [ ] Migrate tests to new interface
- [ ] Ensure backward compatibility
- [ ] Add feature flags for hardware backends

**Feature Flags**:
```toml
[features]
default = ["software-keys"]
software-keys = []
tpm2 = ["tpm2-tss"]
secure-element = ["cryptoauth-rs"]
trustzone = ["optee-rs"]
sgx = ["sgx-sdk"]
```

---

## 📅 Phase 2: TPM 2.0 Integration (Weeks 3-6)

### Week 3: TPM Foundation
**Platform**: Linux (tpm2-tss), Windows (TBS)

#### Tasks
- [ ] Add tpm2-tss dependency
- [ ] Implement TPM key creation
- [ ] Implement TPM signing operations
- [ ] Handle TPM sessions and authentication

**Code Structure**:
```rust
// src/lib/src/platform/tpm2/mod.rs
pub struct Tpm2Provider {
    context: tpm2_tss::Context,
}

impl SecureKeyProvider for Tpm2Provider {
    fn generate_key(&self) -> Result<KeyHandle, WSError> {
        // Use TPM2_Create with signing key template
        // Store in persistent handle
    }

    fn sign(&self, handle: KeyHandle, data: &[u8]) -> Result<Vec<u8>, WSError> {
        // Use TPM2_Sign
        // Keys never leave TPM
    }
}
```

### Week 4-5: TPM Testing & Hardening
- [ ] Unit tests with TPM simulator
- [ ] Integration tests with real TPM hardware
- [ ] Error handling for TPM-specific issues
- [ ] PCR policy support for secure boot
- [ ] Key hierarchy management

### Week 6: Windows TPM Support
- [ ] Windows TBS (TPM Base Services) integration
- [ ] Cross-platform TPM abstraction
- [ ] Windows-specific tests

**Targets**:
- Linux: `/dev/tpm0`, `/dev/tpmrm0`
- Windows: TBS API
- Embedded Linux: tpm2-tss with custom TCTI

---

## 📅 Phase 3: Secure Element Support (Weeks 7-10)

### Week 7-8: ATECC608 Integration
**Target**: IoT devices, ARM Cortex-M

#### Tasks
- [ ] I2C communication layer
- [ ] ATECC608 key slot management
- [ ] ECC P-256 signing via hardware
- [ ] Secure key generation with hardware RNG

**Platform Support**:
```rust
// src/lib/src/platform/secure_element/atecc608.rs
pub struct Atecc608Provider {
    device: cryptoauth::Device,
    key_slot: u8,
}

impl SecureKeyProvider for Atecc608Provider {
    fn generate_key(&self) -> Result<KeyHandle, WSError> {
        // Generate key in secure element
        // Key never readable, only usable
        self.device.gen_key(self.key_slot, true)?;
        Ok(KeyHandle::SecureElement(self.key_slot))
    }
}
```

### Week 9-10: SE050 Support
**Target**: Industrial IoT, NXP platforms

- [ ] SE050 applet integration
- [ ] Policy-based key usage
- [ ] Attestation support
- [ ] Secure channel establishment

---

## 📅 Phase 4: Offline Certificate Mode (Weeks 11-14)

### Week 11-12: Certificate Provisioning
**Goal**: Factory/manufacturing-time provisioning

#### Components
- [ ] Certificate generation tools
- [ ] Key injection utilities
- [ ] Provisioning protocol design
- [ ] Manufacturing workflow

**Workflow**:
```
Factory Floor:
1. Generate keys in secure facility
2. Create CSR with device identity
3. Sign with private CA
4. Inject cert + intermediate CA into device
5. Lock down key storage

Device Side:
1. Load provisioned certificate
2. Sign WASM modules with hardware-backed key
3. Include cert chain in signature
4. No internet required
```

### Week 13-14: Offline Verification
- [ ] Embedded CA trust store
- [ ] Certificate chain validation
- [ ] CRL/OCSP for revocation (optional)
- [ ] Time-based validity checks

**Architecture**:
```rust
pub struct ProvisionedKey {
    key_handle: KeyHandle,
    certificate_chain: Vec<Certificate>,
    private_ca_root: Certificate,
}

impl ProvisionedKey {
    pub fn sign_offline(&self, module: Module) -> Result<SignedModule, WSError> {
        // Sign with hardware-backed key
        let signature = self.provider.sign(self.key_handle, &hash)?;

        // Embed certificate chain (not public key)
        // Verifiers use embedded CA root
        Ok(SignedModule::with_certificate(signature, self.certificate_chain))
    }
}
```

---

## 📅 Phase 5: Platform-Specific Integration (Weeks 15-18)

### Week 15-16: ARM TrustZone
**Target**: ARM Cortex-A, secure world

- [ ] OP-TEE trusted application
- [ ] Secure world key storage
- [ ] REE (Rich Execution Environment) communication
- [ ] Attestation with secure boot

**OP-TEE Architecture**:
```
Normal World (Linux):       Secure World (OP-TEE):
┌──────────────┐           ┌──────────────┐
│     wsc      │  ←SMC→    │  Signing TA  │
│   (client)   │           │  (keys here) │
└──────────────┘           └──────────────┘
```

### Week 17: Intel SGX (x86)
**Target**: Server/edge with SGX

- [ ] SGX enclave for key operations
- [ ] Sealed key storage
- [ ] Remote attestation
- [ ] Enclave signing interface

### Week 18: Platform Testing Matrix
- [ ] Linux x86_64 + TPM
- [ ] Linux ARM + TrustZone
- [ ] Windows + TPM
- [ ] Embedded Linux + ATECC608
- [ ] Bare metal + SE050

---

## 📅 Phase 6: Testing & Validation (Weeks 19-22)

### Week 19-20: Security Testing
- [ ] Fuzzing with AFL/cargo-fuzz
- [ ] Side-channel analysis
- [ ] Fault injection testing
- [ ] Memory safety validation
- [ ] Timing attack resistance

**Test Cases**:
```rust
#[test]
fn test_key_never_leaves_hardware() {
    // Verify keys not in process memory
    // Use memory scanning techniques
}

#[test]
fn test_timing_attack_resistance() {
    // Constant-time validation checks
}

#[test]
fn test_secure_boot_integration() {
    // Verify PCR policies work
}
```

### Week 21: Integration Testing
- [ ] End-to-end embedded workflows
- [ ] Cross-platform signing/verification
- [ ] Factory provisioning simulation
- [ ] Secure firmware update flow

### Week 22: Performance Benchmarking
- [ ] Hardware signing latency
- [ ] Memory usage on embedded targets
- [ ] Power consumption analysis
- [ ] Throughput testing

---

## 📅 Phase 7: Documentation & Release (Weeks 23-24)

### Week 23: Documentation
- [ ] Embedded deployment guide
- [ ] Platform-specific setup instructions
- [ ] Manufacturing provisioning guide
- [ ] Security best practices
- [ ] Threat model documentation
- [ ] API reference documentation

### Week 24: Release Preparation
- [ ] Security audit (external)
- [ ] Dependency audit and cleanup
- [ ] Version 1.0.0 release planning
- [ ] Migration guides
- [ ] Example projects for each platform

---

## 🏗️ Technical Architecture

### Module Structure
```
src/
├── lib/
│   ├── platform/           # NEW: Hardware abstraction
│   │   ├── mod.rs         # SecureKeyProvider trait
│   │   ├── software.rs    # Existing software keys
│   │   ├── tpm2/          # TPM 2.0 support
│   │   │   ├── linux.rs
│   │   │   └── windows.rs
│   │   ├── secure_element/
│   │   │   ├── atecc608.rs
│   │   │   └── se050.rs
│   │   ├── trustzone/     # ARM TrustZone
│   │   │   └── optee.rs
│   │   └── sgx/           # Intel SGX
│   │       └── enclave.rs
│   ├── provisioning/       # NEW: Factory provisioning
│   │   ├── certificate.rs
│   │   └── factory.rs
│   └── signature/
│       └── keyless/       # Existing Sigstore
└── tools/                  # NEW: Provisioning tools
    ├── provision/
    └── verify/
```

### Dependency Tree
```toml
[dependencies]
# Existing
ed25519-compact = "2.1"
p256 = "0.13"
zeroize = { version = "1.8", features = ["derive"] }

# NEW: Hardware backends (feature-gated)
tpm2-tss = { version = "0.1", optional = true }
cryptoauth-rs = { version = "0.3", optional = true }  # ATECC608
optee-rs = { version = "0.1", optional = true }       # TrustZone
sgx-sdk = { version = "2.0", optional = true }        # Intel SGX
pkcs11 = { version = "0.5", optional = true }         # Generic HSM

# NEW: Certificate handling
x509-cert = "0.2"
rustls-pemfile = "2.0"
```

---

## 🎓 Training & Knowledge Transfer

### Week 4, 8, 12, 16, 20, 24: Knowledge Shares
- Internal presentations on each phase
- Architecture decision records (ADRs)
- Code walkthroughs
- Security considerations

### Documentation Requirements
- Architecture diagrams
- Sequence diagrams for key operations
- Platform setup guides
- Troubleshooting guides

---

## 💰 Resource Requirements

### Personnel
- **Lead Developer**: Full-time, 6 months
- **Security Reviewer**: Part-time, ongoing
- **Embedded Systems Engineer**: Part-time (Phases 3-5)
- **QA/Testing**: Part-time (Phase 6)

### Hardware
- TPM 2.0 development boards ($200-500)
- ATECC608 evaluation kits ($50-100)
- SE050 development kits ($100-200)
- ARM TrustZone development boards ($300-500)
- Intel SGX-capable machines (if not existing)

### Software/Services
- TPM simulator (free, tpm2-simulator)
- Hardware testing lab access
- Security audit ($10k-30k, optional but recommended)
- CI/CD for multiple platforms

---

## 🚧 Risk Management

### Technical Risks
| Risk | Impact | Mitigation |
|------|--------|------------|
| TPM compatibility issues | HIGH | Test with multiple vendors, use simulator |
| Secure element driver availability | MEDIUM | Provide reference implementations |
| Cross-platform complexity | HIGH | Strong abstraction layer, comprehensive tests |
| Performance on embedded targets | MEDIUM | Early benchmarking, optimization phase |

### Schedule Risks
| Risk | Impact | Mitigation |
|------|--------|------------|
| Hardware procurement delays | MEDIUM | Order early, use simulators |
| Platform-specific bugs | HIGH | Buffer time in schedule |
| Dependency on external libraries | MEDIUM | Evaluate alternatives early |

---

## 📊 Success Metrics

### Phase 1-2 (Foundation + TPM)
- [ ] All tests pass with software and TPM backends
- [ ] No secret keys in process memory (verified)
- [ ] <100ms signing latency with TPM
- [ ] Zero critical security findings

### Phase 3-4 (SE + Offline)
- [ ] Factory provisioning workflow documented
- [ ] Successful signing on ARM Cortex-M
- [ ] Offline verification works without internet
- [ ] Certificate chain validation complete

### Phase 5-6 (Platform + Testing)
- [ ] 5+ platforms supported
- [ ] >90% test coverage for hardware paths
- [ ] Fuzzing runs 1M+ iterations without crash
- [ ] External security audit passed

### Phase 7 (Release)
- [ ] Documentation complete
- [ ] Migration guides published
- [ ] Example projects for 3+ platforms
- [ ] v1.0.0 released

---

## 🎯 Decision Points

### After Phase 2 (Week 6)
**Decision**: Continue with SE support or focus on TPM maturity?
- If TPM adoption is main use case → invest more in TPM features
- If IoT is priority → proceed to Phase 3

### After Phase 4 (Week 14)
**Decision**: Breadth vs. Depth?
- Breadth: Support more platforms (Phase 5)
- Depth: Advanced features (attestation, key rotation)

### After Phase 6 (Week 22)
**Decision**: Release timeline?
- If security audit reveals issues → extend Phase 6
- If ready → proceed to release

---

## 📝 Open Questions

1. **Primary target platform**: Which embedded platform is highest priority?
   - [ ] Linux ARM + TPM (industrial)
   - [ ] ATECC608 (IoT)
   - [ ] TrustZone (mobile/automotive)

2. **Certificate management**: Who manages the private CA?
   - [ ] Provide CA tools?
   - [ ] Integrate with existing PKI?
   - [ ] SaaS offering for small deployments?

3. **Backward compatibility**: Support existing signatures?
   - [ ] Yes, read-only
   - [ ] Yes, with migration path
   - [ ] No, breaking change

4. **Performance targets**: What's acceptable latency?
   - [ ] <50ms (challenging)
   - [ ] <100ms (reasonable)
   - [ ] <500ms (acceptable for embedded)

---

## 🚀 Getting Started (Next 24 Hours)

### Immediate Actions
1. ✅ Fix critical security issues (Debug output)
2. ✅ Add zeroization
3. 🚧 Design SecureKeyProvider trait
4. 🚧 Set up feature flags
5. 🚧 Order hardware for testing

### First Week Goals
- Security fixes merged
- Hardware abstraction layer designed
- TPM simulator setup complete
- First draft of embedded API

---

## 📞 Stakeholder Communication

### Weekly Updates
- Progress against roadmap
- Blockers and risks
- Demo of new capabilities
- Updated timeline

### Monthly Reviews
- Phase completion assessment
- Architecture review
- Security posture update
- Go/no-go decisions

---

## 🎉 Vision: 6 Months From Now

```rust
// Developer using wsc in embedded context
fn sign_firmware() -> Result<(), WSError> {
    // Automatic platform detection
    let provider = SecureKeyProvider::detect()?;

    match provider {
        Platform::Tpm2 => {
            println!("Using TPM 2.0 for signing");
        }
        Platform::Atecc608 => {
            println!("Using secure element for signing");
        }
        Platform::TrustZone => {
            println!("Using ARM TrustZone for signing");
        }
    }

    let key = provider.load_key("firmware-signing-key")?;
    let firmware = Module::from_file("firmware.wasm")?;
    let signed = key.sign(firmware)?;
    signed.save("firmware.signed.wasm")?;

    println!("✅ Firmware signed with hardware-backed key");
    Ok(())
}
```

**Result**: Production-ready WebAssembly signing for embedded systems with hardware security!
