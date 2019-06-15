use std::hash::Hash;

use crypto::digest::Digest;
use crypto::sha2::Sha256;

use crate::block::Sha256Hash;
use crate::transaction::Transaction;

pub(crate) struct MerkelTree {
    pub(crate) root_node: MerkelNode,
    pub(crate) count: usize,
    pub(crate) height: usize,
}

pub(crate) enum MerkelNode {
    Empty {
        hash: Sha256Hash,
    },
    Node {
        hash: Sha256Hash,
        left: Box<MerkelNode>,
        right: Box<MerkelNode>,
    },
    Leaf {
        hash: Sha256Hash,
        value: Vec<u8>,
    },
}

impl MerkelNode {
    pub fn empty(hash: Sha256Hash) -> MerkelNode {
        MerkelNode::Empty { hash }
    }
    pub fn leaf(value: Vec<u8>) -> MerkelNode {
        let mut hasher = Sha256::new();
        let mut hash = Sha256Hash::default();
        hasher.input(&value);
        hasher.result(&mut hash);
        MerkelNode::Leaf { hash, value }
    }
    pub fn node(left: MerkelNode, right: MerkelNode) -> MerkelNode {
        let mut hasher = Sha256::new();
        let mut hash = Sha256Hash::default();
        let mut value = Vec::new();
        value.extend_from_slice(left.hash());
        value.extend_from_slice(right.hash());
        hasher.input(&value);
        hasher.result(&mut hash);
        MerkelNode::Node {
            hash,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
    pub fn hash(&self) -> &Sha256Hash {
        match *self {
            MerkelNode::Empty { ref hash } => hash,
            MerkelNode::Leaf { ref hash, .. } => hash,
            MerkelNode::Node { ref hash, .. } => hash,
        }
    }
}

impl MerkelTree {
    pub fn new(mut transactions: Vec<Vec<u8>>) -> MerkelTree {
        if transactions.is_empty() {
            return MerkelTree {
                root_node: MerkelNode::empty(Sha256Hash::default()),
                count: 0,
                height: 0,
            };
        }
        let count = transactions.len();
        let mut cur = Vec::with_capacity(count);
        let mut height = 0;
        for v in transactions {
            let leaf = MerkelNode::leaf(v);
            cur.push(leaf);
        }
        while cur.len() > 1 {
            let mut next = Vec::new();
            while !cur.is_empty() {
                if cur.len() == 1 {
                    next.push(cur.remove(0))
                } else {
                    let left = cur.remove(0);
                    let right = cur.remove(0);
                    let node = MerkelNode::node(left, right);
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
}
