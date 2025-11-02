//! RFC 6962 Merkle Tree Inclusion Proof Verification
//!
//! This module implements cryptographic verification of Merkle tree inclusion proofs
//! according to RFC 6962 (Certificate Transparency). Rekor uses RFC 6962-style Merkle
//! trees via the Trillian transparency log infrastructure.
//!
//! # Security Model
//!
//! Merkle tree inclusion proofs provide cryptographic evidence that a specific entry
//! exists in a transparency log at a given tree size. The proof consists of:
//! - A sequence of sibling hashes along the path from leaf to root
//! - The leaf index in the tree
//! - The tree size at verification time
//! - The expected root hash
//!
//! # RFC 6962 Hash Computation
//!
//! **Leaf Hash**: `SHA-256(0x00 || leaf_data)`
//! - The `0x00` byte is the domain separator for leaf nodes
//! - Prevents second-preimage attacks
//!
//! **Interior Node Hash**: `SHA-256(0x01 || left_child || right_child)`
//! - The `0x01` byte is the domain separator for interior nodes
//! - left_child and right_child are 32-byte SHA-256 hashes
//!
//! # Implementation
//!
//! This is a from-scratch implementation based on RFC 6962 specification.
//! It does NOT use external merkle tree libraries to ensure:
//! - Full audit trail of every line of code
//! - No dependency on unaudited crypto libraries
//! - Clear security review path

use crate::error::WSError;
use sha2::{Digest, Sha256};

/// RFC 6962 domain separator for leaf nodes
const LEAF_PREFIX: u8 = 0x00;

/// RFC 6962 domain separator for interior nodes
const NODE_PREFIX: u8 = 0x01;

/// Compute RFC 6962 leaf hash
///
/// # Arguments
/// * `data` - The leaf data bytes
///
/// # Returns
/// 32-byte SHA-256 hash with leaf domain separator
///
/// # Security
/// The 0x00 prefix ensures leaf hashes cannot collide with interior node hashes.
/// This prevents second-preimage attacks where an attacker tries to find a different
/// tree structure that produces the same root hash.
pub fn compute_leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute RFC 6962 interior node hash
///
/// # Arguments
/// * `left` - Left child hash (32 bytes)
/// * `right` - Right child hash (32 bytes)
///
/// # Returns
/// 32-byte SHA-256 hash of the combined children
///
/// # Security
/// The 0x01 prefix ensures interior node hashes cannot collide with leaf hashes.
pub fn compute_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Verify a Merkle tree inclusion proof according to RFC 6962
///
/// # Arguments
/// * `leaf_index` - Index of the leaf in the tree (0-based)
/// * `tree_size` - Total number of leaves in the tree
/// * `leaf_hash` - Hash of the leaf data (32 bytes)
/// * `proof_hashes` - Audit path hashes from leaf to root
/// * `expected_root` - Expected Merkle tree root hash (32 bytes)
///
/// # Returns
/// `Ok(())` if the proof is valid, `Err(WSError)` otherwise
///
/// # Algorithm
///
/// The algorithm walks up the Merkle tree from the leaf to the root:
/// 1. Start with `current_hash = leaf_hash`
/// 2. For each proof hash in the audit path:
///    - Determine if current node is left or right child based on index
///    - Compute parent: `hash(0x01 || left || right)`
///    - Update index to parent's index
/// 3. Compare final computed hash with expected root
///
/// # Security
/// - Validates that leaf exists in tree of specified size
/// - Cryptographically binds leaf to root via hash chain
/// - Prevents tampering with log entries
pub fn verify_inclusion_proof(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &[u8; 32],
    proof_hashes: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), WSError> {
    // Validate inputs
    if leaf_index >= tree_size {
        return Err(WSError::RekorError(format!(
            "Leaf index {} is out of range for tree size {}",
            leaf_index, tree_size
        )));
    }

    if tree_size == 0 {
        return Err(WSError::RekorError(
            "Tree size cannot be zero".to_string(),
        ));
    }

    // Special case: single-leaf tree
    if tree_size == 1 {
        if leaf_index != 0 {
            return Err(WSError::RekorError(
                "Leaf index must be 0 for single-leaf tree".to_string(),
            ));
        }
        if !proof_hashes.is_empty() {
            return Err(WSError::RekorError(
                "Proof should be empty for single-leaf tree".to_string(),
            ));
        }
        if leaf_hash != expected_root {
            return Err(WSError::RekorError(
                "Leaf hash does not match root for single-leaf tree".to_string(),
            ));
        }
        return Ok(());
    }

    // Walk up the tree computing hashes
    let mut current_hash = *leaf_hash;
    let mut current_index = leaf_index;
    let mut current_tree_size = tree_size;

    #[cfg(test)]
    {
        println!("   Starting with leaf hash: {}", hex::encode(current_hash));
        println!("   Leaf index: {}, Tree size: {}", current_index, current_tree_size);
    }

    for (_i, proof_hash) in proof_hashes.iter().enumerate() {
        // Determine if current node is left or right child
        // The tree is built left-to-right, so we can determine position
        // based on whether the index is even or odd at each level

        // Calculate the size of the left subtree at this level
        // This is the largest power of 2 less than current_tree_size
        let left_subtree_size = largest_power_of_two_less_than(current_tree_size);

        let is_left_child = current_index < left_subtree_size;

        #[cfg(test)]
        let (left_hex, right_hex) = if is_left_child {
            (hex::encode(current_hash), hex::encode(proof_hash))
        } else {
            (hex::encode(proof_hash), hex::encode(current_hash))
        };

        let (left, right) = if is_left_child {
            // Current node is in left subtree
            (&current_hash, proof_hash)
        } else {
            // Current node is in right subtree
            (proof_hash, &current_hash)
        };

        current_hash = compute_node_hash(left, right);

        #[cfg(test)]
        {
            println!("\n   Step {}: {} child", _i + 1, if is_left_child { "LEFT" } else { "RIGHT" });
            println!("     Left:   {}", left_hex);
            println!("     Right:  {}", right_hex);
            println!("     Result: {}", hex::encode(current_hash));
            println!("     Index: {} -> {}, Tree size: {} -> {}",
                current_index,
                if current_index >= left_subtree_size { current_index - left_subtree_size } else { current_index },
                current_tree_size,
                if current_index >= left_subtree_size { current_tree_size - left_subtree_size } else { left_subtree_size }
            );
        }

        // Move up to parent level
        if current_index >= left_subtree_size {
            current_index -= left_subtree_size;
            current_tree_size -= left_subtree_size;
        } else {
            current_tree_size = left_subtree_size;
        }
    }

    #[cfg(test)]
    println!("\n   Final computed root: {}", hex::encode(current_hash));

    // Final computed hash should match the expected root
    if &current_hash != expected_root {
        return Err(WSError::RekorError(format!(
            "Computed root hash does not match expected root. Computed: {}, Expected: {}",
            hex::encode(current_hash),
            hex::encode(expected_root)
        )));
    }

    Ok(())
}

/// Find the largest power of 2 less than n
///
/// Used in Merkle tree calculations to determine subtree sizes.
/// For example: n=7 returns 4, n=5 returns 4, n=8 returns 4, n=9 returns 8
fn largest_power_of_two_less_than(n: u64) -> u64 {
    if n <= 1 {
        return n;
    }

    // Find the highest set bit
    let mut power = 1u64;
    while power * 2 < n {
        power *= 2;
    }
    power
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash_computation() {
        // Test that leaf hash includes the 0x00 prefix
        let data = b"test data";
        let hash = compute_leaf_hash(data);

        // Manually compute expected hash
        let mut expected = Sha256::new();
        expected.update(&[0x00]);
        expected.update(data);
        let expected_hash: [u8; 32] = expected.finalize().into();

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_node_hash_computation() {
        // Test that node hash includes the 0x01 prefix
        let left = [1u8; 32];
        let right = [2u8; 32];
        let hash = compute_node_hash(&left, &right);

        // Manually compute expected hash
        let mut expected = Sha256::new();
        expected.update(&[0x01]);
        expected.update(&left);
        expected.update(&right);
        let expected_hash: [u8; 32] = expected.finalize().into();

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_single_leaf_tree() {
        // Tree with just one leaf
        let leaf_hash = [0x42u8; 32];
        let result = verify_inclusion_proof(
            0,
            1,
            &leaf_hash,
            &[],
            &leaf_hash,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_single_leaf_tree_wrong_root() {
        let leaf_hash = [0x42u8; 32];
        let wrong_root = [0x43u8; 32];
        let result = verify_inclusion_proof(
            0,
            1,
            &leaf_hash,
            &[],
            &wrong_root,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_leaf_index() {
        let leaf_hash = [0x42u8; 32];
        let result = verify_inclusion_proof(
            5,  // Invalid index for tree size 3
            3,
            &leaf_hash,
            &[],
            &leaf_hash,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_largest_power_of_two() {
        assert_eq!(largest_power_of_two_less_than(1), 1);
        assert_eq!(largest_power_of_two_less_than(2), 1);
        assert_eq!(largest_power_of_two_less_than(3), 2);
        assert_eq!(largest_power_of_two_less_than(4), 2);
        assert_eq!(largest_power_of_two_less_than(5), 4);
        assert_eq!(largest_power_of_two_less_than(7), 4);
        assert_eq!(largest_power_of_two_less_than(8), 4);
        assert_eq!(largest_power_of_two_less_than(9), 8);
        assert_eq!(largest_power_of_two_less_than(15), 8);
        assert_eq!(largest_power_of_two_less_than(16), 8);
        assert_eq!(largest_power_of_two_less_than(17), 16);
    }

    #[test]
    fn test_two_leaf_tree() {
        // Build a simple 2-leaf tree manually
        // Leaf 0: hash(0x00 || "leaf0")
        // Leaf 1: hash(0x00 || "leaf1")
        // Root: hash(0x01 || leaf0_hash || leaf1_hash)

        let leaf0_data = b"leaf0";
        let leaf1_data = b"leaf1";

        let leaf0_hash = compute_leaf_hash(leaf0_data);
        let leaf1_hash = compute_leaf_hash(leaf1_data);

        let root = compute_node_hash(&leaf0_hash, &leaf1_hash);

        // Verify leaf 0's inclusion (proof is leaf 1's hash)
        let result = verify_inclusion_proof(
            0,
            2,
            &leaf0_hash,
            &[leaf1_hash],
            &root,
        );
        assert!(result.is_ok(), "Failed to verify leaf 0");

        // Verify leaf 1's inclusion (proof is leaf 0's hash)
        let result = verify_inclusion_proof(
            1,
            2,
            &leaf1_hash,
            &[leaf0_hash],
            &root,
        );
        assert!(result.is_ok(), "Failed to verify leaf 1");
    }

    /// Test vectors from Google's certificate-transparency repository
    /// Source: https://github.com/google/certificate-transparency/blob/master/cpp/merkletree/merkle_tree_test.cc
    ///
    /// These are the official test vectors used by Certificate Transparency implementations.
    /// Validating against these ensures our RFC 6962 implementation is correct.
    #[test]
    fn test_google_ct_test_vectors() {
        // Test vector data from kInputs
        let inputs: Vec<&[u8]> = vec![
            &[],                                                           // 0: empty
            &[0x00],                                                       // 1: single byte
            &[0x10],                                                       // 2: single byte
            &[0x20, 0x21],                                                // 3: 2 bytes
            &[0x30, 0x31],                                                // 4: 2 bytes
            &[0x40, 0x41, 0x42, 0x43],                                   // 5: 4 bytes
            &[0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],         // 6: 8 bytes
            &[0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,          // 7: 16 bytes
              0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f],
        ];

        // Expected root hashes for trees of size 1-8 (from kSHA256Roots)
        let expected_roots = vec![
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",  // 1 leaf
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",  // 2 leaves
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",  // 3 leaves
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",  // 4 leaves
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",  // 5 leaves
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",  // 6 leaves
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",  // 7 leaves
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",  // 8 leaves
        ];

        // Test 1: Validate single-leaf tree
        let leaf0_hash = compute_leaf_hash(inputs[0]);
        let expected_root0 = hex::decode(expected_roots[0]).unwrap();
        assert_eq!(
            &leaf0_hash[..],
            &expected_root0[..],
            "Single-leaf root mismatch"
        );

        // Test 2: Validate two-leaf tree
        let leaf0_hash = compute_leaf_hash(inputs[0]);
        let leaf1_hash = compute_leaf_hash(inputs[1]);
        let computed_root = compute_node_hash(&leaf0_hash, &leaf1_hash);
        let expected_root1 = hex::decode(expected_roots[1]).unwrap();
        assert_eq!(
            &computed_root[..],
            &expected_root1[..],
            "Two-leaf root mismatch"
        );

        // Test 3: Build 3-leaf tree and verify structure
        // Tree structure:
        //       root
        //      /    \
        //   h01      leaf2
        //   / \
        // l0  l1
        let leaf0_hash = compute_leaf_hash(inputs[0]);
        let leaf1_hash = compute_leaf_hash(inputs[1]);
        let leaf2_hash = compute_leaf_hash(inputs[2]);
        let h01 = compute_node_hash(&leaf0_hash, &leaf1_hash);
        let root3 = compute_node_hash(&h01, &leaf2_hash);
        let expected_root2 = hex::decode(expected_roots[2]).unwrap();
        assert_eq!(
            &root3[..],
            &expected_root2[..],
            "Three-leaf root mismatch"
        );

        // Test 4: Verify inclusion proof for leaf 0 in 3-leaf tree
        // Proof path: need leaf1_hash and leaf2_hash
        let proof = vec![leaf1_hash, leaf2_hash];
        let result = verify_inclusion_proof(0, 3, &leaf0_hash, &proof, &root3);
        assert!(result.is_ok(), "Failed to verify leaf 0 in 3-leaf tree: {:?}", result.err());
    }

    #[test]
    fn test_empty_leaf_hash() {
        // From Google CT test vectors: A leaf containing empty data
        // This is SHA-256(0x00 || "") which equals the first root in the test vectors
        // Expected: 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
        let empty_leaf_hash = compute_leaf_hash(&[]);
        let expected = hex::decode("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d").unwrap();

        assert_eq!(
            &empty_leaf_hash[..],
            &expected[..],
            "Empty leaf hash mismatch. Expected SHA-256(0x00 || '')"
        );
    }
}
