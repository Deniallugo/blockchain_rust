use std::hash::Hash;

use crate::block::Sha256Hash;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::slice::Iter;

pub(crate) struct MerkelTree {
    pub(crate) root_node: MerkelNode,
    pub(crate) count: usize,
    pub(crate) height: usize,
}
#[derive(Debug, Clone)]
pub(crate) enum MerkelNode {
    Empty {
        hash: Sha256Hash,
    },
    Node {
        hash: Sha256Hash,
        left: Box<MerkelNode>,
        right: Box<MerkelNode>,
        indexes: Vec<usize>,
    },
    Leaf {
        hash: Sha256Hash,
        value: Vec<u8>,
        index: usize,
    },
}

fn calculate_hash(left: &Sha256Hash, right: &Sha256Hash) -> Sha256Hash {
    let mut hasher = Sha256::new();
    let mut hash = Sha256Hash::default();
    let mut value = Vec::new();
    value.extend_from_slice(left);
    value.extend_from_slice(right);
    hasher.input(&value);
    hasher.result(&mut hash);
    hash
}

impl MerkelNode {
    pub fn empty(hash: Sha256Hash) -> MerkelNode {
        MerkelNode::Empty { hash }
    }

    pub fn leaf(value: Vec<u8>, index: usize) -> MerkelNode {
        let mut hasher = Sha256::new();
        let mut hash = Sha256Hash::default();
        hasher.input(&value);
        hasher.result(&mut hash);
        MerkelNode::Leaf { hash, value, index }
    }

    pub fn node(left: MerkelNode, right: MerkelNode, indexes: Vec<usize>) -> MerkelNode {
        let hash = calculate_hash(left.hash(), right.hash());
        MerkelNode::Node {
            hash,
            left: Box::new(left),
            right: Box::new(right),
            indexes,
        }
    }

    pub fn hash(&self) -> &Sha256Hash {
        match *self {
            MerkelNode::Empty { ref hash } => hash,
            MerkelNode::Leaf { ref hash, .. } => hash,
            MerkelNode::Node { ref hash, .. } => hash,
        }
    }
    pub fn indexes(&self) -> Vec<usize> {
        match self {
            MerkelNode::Empty { .. } => vec![0],
            MerkelNode::Leaf { index, .. } => vec![index.clone()],
            MerkelNode::Node { indexes, .. } => indexes.clone(),
        }
    }
}

impl PartialEq for MerkelNode {
    fn eq(&self, other: &Self) -> bool {
        use MerkelNode::*;
        return match (self, other) {
            (Leaf { hash: a, .. }, Leaf { hash: b, .. }) => a == b,
            (Node { hash: a, .. }, Node { hash: b, .. }) => a == b,
            (Empty { hash: a }, Empty { hash: b }) => a == b,
            _ => false,
        };
    }
}

impl MerkelTree {
    pub fn new(transactions: Vec<Vec<u8>>) -> MerkelTree {
        if transactions.is_empty() {
            return MerkelTree {
                root_node: MerkelNode::empty(Sha256Hash::default()),
                count: 0,
                height: 0,
            };
        }

        let count = transactions.len();
        let mut cur = vec![];
        for (i, v) in transactions.into_iter().enumerate() {
            cur.push(MerkelNode::leaf(v, i));
        }
        let mut height = 1;

        while cur.len() > 1 {
            let mut next = Vec::new();
            while !cur.is_empty() {
                if cur.len() == 1 {
                    next.push(cur.remove(0))
                } else {
                    let left = cur.remove(0);
                    let right = cur.remove(0);
                    let indexes = [left.indexes(), right.indexes()].concat();
                    let node = MerkelNode::node(left, right, indexes);
                    next.push(node);
                }
            }
            height += 1;
            cur = next;
        }
        let root_node = cur.remove(0);

        MerkelTree {
            root_node,
            count,
            height,
        }
    }

    fn get_proof(&self, hash: &Sha256Hash, index: usize) -> (Vec<bool>, Vec<Sha256Hash>) {
        next_step_proof(&Box::new(self.root_node.clone()), index, hash)
    }

    fn reconstruct_root(
        &self,
        hashes: Vec<Sha256Hash>,
        bit_mask: Vec<bool>,
    ) -> Result<Sha256Hash, ()> {
        if hashes.len() != bit_mask.len() {
            unreachable!()
        }
        let node = construct(0, &mut hashes.iter(), &mut bit_mask.iter(), self.height);
        return Ok(node.hash().clone());

        fn construct(
            depth: usize,
            hash_iter: &mut Iter<Sha256Hash>,
            bit_mask_iter: &mut Iter<bool>,
            max_depth: usize,
        ) -> MerkelNode {
            let bit = bit_mask_iter.next().unwrap();
            let hash = hash_iter.next().unwrap();

            if depth == max_depth {
                return MerkelNode::Leaf {
                    hash: hash.clone(),
                    value: vec![],
                    index: 0,
                };
            } else if *bit {
                let left = construct(depth + 1, hash_iter, bit_mask_iter, max_depth);
                let right = construct(depth + 1, hash_iter, bit_mask_iter, max_depth);
                MerkelNode::node(left, right, vec![])
            } else {
                MerkelNode::Leaf {
                    hash: hash.clone(),
                    value: vec![],
                    index: 0,
                }
            }
        }
    }
}

fn next_step_proof(
    node: &Box<MerkelNode>,
    target_index: usize,
    target_hash: &Sha256Hash,
) -> (Vec<bool>, Vec<Sha256Hash>) {
    match &**node {
        MerkelNode::Empty { hash } => {
            let hashes = vec![hash.clone()];
            let bit_mask = vec![];
            (bit_mask, hashes)
        }

        MerkelNode::Node {
            hash,
            left,
            right,
            indexes,
        } => {
            if indexes.contains(&target_index) {
                let hashes = vec![hash.clone()];
                let bit_mask = vec![true];

                let (left_bits, left_hashes) = next_step_proof(&left, target_index, target_hash);
                let mut new_bit = [bit_mask, left_bits].concat();
                let mut new_hashes = [hashes, left_hashes].concat();

                let (right_bit, right_hashes) = next_step_proof(&right, target_index, target_hash);
                let new_bit = [new_bit, right_bit].concat();
                let new_hashes = [new_hashes, right_hashes].concat();
                (new_bit, new_hashes)
            } else {
                let hashes = vec![hash.clone()];
                let bit_mask = vec![false];
                (bit_mask, hashes)
            }
        }

        MerkelNode::Leaf { hash, index, .. } => {
            let hashes;
            let bit_mask;
            if target_index != *index {
                hashes = vec![hash.clone()];
                bit_mask = vec![false];
            } else {
                hashes = vec![target_hash.clone()];
                bit_mask = vec![false];
            }
            (bit_mask, hashes)
        }
    }
}

mod tests {
    use super::*;
    #[test]
    fn create_merkel_tree() {
        let mut transactions = Vec::new();
        let count = 5;
        for _ in 0..count {
            let tx = vec![0, 1, 2, 3];
            transactions.push(tx)
        }
        let a = MerkelTree::new(transactions);
        assert_eq!(a.height, 3);
        assert_eq!(a.count, count);
    }
    #[test]
    fn create_verification_proof() {
        let mut transactions = Vec::new();
        let count: u32 = 5;
        for i in 0..count {
            let tx = vec![0, 1, 2, i as u8];
            transactions.push(tx)
        }
        let a = MerkelNode::leaf(transactions[2].clone(), 0);
        let mt = MerkelTree::new(transactions);

        let (bit_mask, hashes) = mt.get_proof(a.hash(), 2);
        assert_eq!(bit_mask, vec![true, true, false, true, false, false, false]);
        let new_root_hash = mt.reconstruct_root(hashes, bit_mask).unwrap();
        assert_eq!(new_root_hash, *mt.root_node.hash());
    }
}
