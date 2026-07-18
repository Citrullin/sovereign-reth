//! Celestia-style Namespaced Merkle Trees for state-diff partitioning.

use alloy_primitives::B256;

/// A namespace ID representing a partition of the manifold state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NamespaceId(pub u64);

/// A Namespaced Merkle Tree Leaf.
#[derive(Debug, Clone)]
pub struct NmtLeaf {
    /// The namespace ID associated with this leaf.
    pub namespace: NamespaceId,
    /// The leaf payload data.
    pub data: Vec<u8>,
}

/// A node in the Namespaced Merkle Tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmtNode {
    /// Minimum namespace ID in this subtree.
    pub min_namespace: NamespaceId,
    /// Maximum namespace ID in this subtree.
    pub max_namespace: NamespaceId,
    /// Commitment hash.
    pub hash: B256,
}

impl NmtNode {
    /// Creates a leaf node commitment.
    pub fn new_leaf(leaf: &NmtLeaf) -> Self {
        let mut hash_data = Vec::new();
        hash_data.extend_from_slice(&leaf.namespace.0.to_be_bytes());
        hash_data.extend_from_slice(&leaf.data);
        
        let hash = alloy_primitives::keccak256(&hash_data);
        Self {
            min_namespace: leaf.namespace,
            max_namespace: leaf.namespace,
            hash,
        }
    }

    /// Combines two child nodes into a parent node.
    pub fn combine(left: &Self, right: &Self) -> Self {
        let min_namespace = std::cmp::min(left.min_namespace, right.min_namespace);
        let max_namespace = std::cmp::max(left.max_namespace, right.max_namespace);

        let mut hash_data = Vec::new();
        hash_data.extend_from_slice(&left.min_namespace.0.to_be_bytes());
        hash_data.extend_from_slice(&left.max_namespace.0.to_be_bytes());
        hash_data.extend_from_slice(left.hash.as_slice());
        hash_data.extend_from_slice(&right.min_namespace.0.to_be_bytes());
        hash_data.extend_from_slice(&right.max_namespace.0.to_be_bytes());
        hash_data.extend_from_slice(right.hash.as_slice());

        let hash = alloy_primitives::keccak256(&hash_data);
        Self {
            min_namespace,
            max_namespace,
            hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nmt_leaf_and_combine() {
        let leaf1 = NmtLeaf {
            namespace: NamespaceId(1),
            data: vec![0x11, 0x12],
        };
        let leaf2 = NmtLeaf {
            namespace: NamespaceId(2),
            data: vec![0x21, 0x22],
        };

        let node1 = NmtNode::new_leaf(&leaf1);
        let node2 = NmtNode::new_leaf(&leaf2);

        assert_eq!(node1.min_namespace, NamespaceId(1));
        assert_eq!(node1.max_namespace, NamespaceId(1));

        let parent = NmtNode::combine(&node1, &node2);
        assert_eq!(parent.min_namespace, NamespaceId(1));
        assert_eq!(parent.max_namespace, NamespaceId(2));
        assert_ne!(parent.hash, B256::ZERO);
    }
}
