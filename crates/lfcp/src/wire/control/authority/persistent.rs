//! Persistent, ordered maps for historical Control states. A compressed binary
//! trie copies only the changed key's path; values and untouched subtrees use
//! `Arc`. Paths are bounded by the fixed key width (64, 256 or 512 bits), not by
//! the chain length. No randomized hashing, whole-map copy or dependency is used.

use std::{collections::BTreeMap, fmt, ops::Index, sync::Arc};

mod sealed {
    pub trait Sealed {}
    impl Sealed for u64 {}
    impl<const N: usize> Sealed for [u8; N] {}
    impl Sealed for ([u8; 32], [u8; 32]) {}
}

/// Fixed-width ordered keys used by [`PersistentMap`]. Implementations are
/// sealed: integers use big-endian bits, IDs/pairs use raw lexicographic order.
pub trait StateKey: sealed::Sealed + Ord + Clone {
    #[doc(hidden)]
    fn bit(&self, bit: usize) -> bool;
    #[doc(hidden)]
    fn differing_bit(&self, other: &Self) -> Option<usize>;
}

impl<const N: usize> StateKey for [u8; N] {
    fn bit(&self, bit: usize) -> bool {
        self[bit / 8] & (0x80 >> (bit % 8)) != 0
    }
    fn differing_bit(&self, other: &Self) -> Option<usize> {
        self.iter().zip(other).enumerate().find_map(|(i, (a, b))| {
            let diff = a ^ b;
            (diff != 0).then(|| i * 8 + diff.leading_zeros() as usize)
        })
    }
}

impl StateKey for u64 {
    fn bit(&self, bit: usize) -> bool {
        self & (1 << (63 - bit)) != 0
    }
    fn differing_bit(&self, other: &Self) -> Option<usize> {
        let diff = self ^ other;
        (diff != 0).then(|| diff.leading_zeros() as usize)
    }
}

impl StateKey for ([u8; 32], [u8; 32]) {
    fn bit(&self, bit: usize) -> bool {
        if bit < 256 {
            self.0.bit(bit)
        } else {
            self.1.bit(bit - 256)
        }
    }
    fn differing_bit(&self, other: &Self) -> Option<usize> {
        self.0
            .differing_bit(&other.0)
            .or_else(|| self.1.differing_bit(&other.1).map(|bit| bit + 256))
    }
}

enum Node<K, V> {
    Leaf(K, Arc<V>),
    Branch {
        bit: usize,
        children: [Arc<Node<K, V>>; 2],
    },
}

impl<K: Clone, V> Clone for Node<K, V> {
    fn clone(&self) -> Self {
        match self {
            Self::Leaf(k, v) => Self::Leaf(k.clone(), v.clone()),
            Self::Branch { bit, children } => Self::Branch {
                bit: *bit,
                children: children.clone(),
            },
        }
    }
}

/// An ordered map whose clones share immutable state. Lookup and update visit
/// at most the fixed key width; a clone is O(1). Updating one entry never copies
/// other values, including their certificate bytes or epoch frontiers.
///
/// The read API mirrors the common `BTreeMap` operations. Mutations preserve
/// every previously cloned map. There is no removal operation: Control state
/// retains roles, bindings and revocations permanently.
pub struct PersistentMap<K, V> {
    root: Option<Arc<Node<K, V>>>,
    len: usize,
}

impl<K, V> Clone for PersistentMap<K, V> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            len: self.len,
        }
    }
}

impl<K, V> Default for PersistentMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> PersistentMap<K, V> {
    /// An empty map, without allocation.
    pub fn new() -> Self {
        Self { root: None, len: 0 }
    }
    /// The number of entries.
    pub fn len(&self) -> usize {
        self.len
    }
    /// Whether no entries have been inserted.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Entries in key order. The traversal stack is bounded by the key width.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut stack: Vec<_> = self.root.as_deref().into_iter().collect();
        std::iter::from_fn(move || {
            while let Some(node) = stack.pop() {
                match node {
                    Node::Leaf(key, value) => return Some((key, value.as_ref())),
                    Node::Branch { children, .. } => {
                        stack.push(&children[1]);
                        stack.push(&children[0]);
                    }
                }
            }
            None
        })
    }
    /// Values in key order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }
}

impl<K: StateKey, V> PersistentMap<K, V> {
    fn leaf(&self, key: &K) -> Option<(&K, &V)> {
        let mut node = self.root.as_deref()?;
        loop {
            match node {
                Node::Leaf(k, v) => return Some((k, v)),
                Node::Branch { bit, children } => node = &children[usize::from(key.bit(*bit))],
            }
        }
    }
    /// The value at `key`, if present.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.leaf(key).filter(|(k, _)| *k == key).map(|(_, v)| v)
    }
    /// Whether `key` is present.
    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }
    /// Insert or replace a value, sharing all other values and subtrees.
    pub fn insert(&mut self, key: K, value: V) {
        let Some((found, _)) = self.leaf(&key) else {
            self.root = Some(Arc::new(Node::Leaf(key, Arc::new(value))));
            self.len = 1;
            return;
        };
        let split = key.differing_bit(found);
        self.len += usize::from(split.is_some());
        Self::insert_at(self.root.as_mut().unwrap(), key, Arc::new(value), split);
    }

    fn insert_at(node: &mut Arc<Node<K, V>>, key: K, value: Arc<V>, split: Option<usize>) {
        if let Node::Branch { bit, .. } = node.as_ref() {
            if split.is_none_or(|split| *bit < split) {
                let Node::Branch { bit, children } = Arc::make_mut(node) else {
                    unreachable!()
                };
                return Self::insert_at(
                    &mut children[usize::from(key.bit(*bit))],
                    key,
                    value,
                    split,
                );
            }
        }
        if let Some(bit) = split {
            let side = usize::from(key.bit(bit));
            let leaf = Arc::new(Node::Leaf(key, value));
            let children = if side == 0 {
                [leaf, node.clone()]
            } else {
                [node.clone(), leaf]
            };
            *node = Arc::new(Node::Branch { bit, children });
        } else {
            *node = Arc::new(Node::Leaf(key, value));
        }
    }
}

impl<K: StateKey, V: Clone> PersistentMap<K, V> {
    /// Mutate one existing value. Only that value and its path are copied if
    /// shared; changes never affect an older head.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if !self.contains_key(key) {
            return None;
        }
        let mut node = self.root.as_mut()?;
        loop {
            match Arc::make_mut(node) {
                Node::Leaf(_, value) => return Some(Arc::make_mut(value)),
                Node::Branch { bit, children } => node = &mut children[usize::from(key.bit(*bit))],
            }
        }
    }
}

impl<K: StateKey, V> Index<&K> for PersistentMap<K, V> {
    type Output = V;
    fn index(&self, key: &K) -> &V {
        self.get(key).expect("key present in Control state")
    }
}

impl<K: StateKey, V> FromIterator<(K, V)> for PersistentMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Self::new();
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}

impl<K: StateKey, V, const N: usize> From<[(K, V); N]> for PersistentMap<K, V> {
    fn from(entries: [(K, V); N]) -> Self {
        entries.into_iter().collect()
    }
}

impl<K: PartialEq, V: PartialEq> PartialEq for PersistentMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        if let (Some(a), Some(b)) = (&self.root, &other.root) {
            if Arc::ptr_eq(a, b) {
                return true;
            }
        }
        self.len == other.len && self.iter().eq(other.iter())
    }
}
impl<K: Eq, V: Eq> Eq for PersistentMap<K, V> {}
impl<K: Ord, V: PartialEq> PartialEq<BTreeMap<K, V>> for PersistentMap<K, V> {
    fn eq(&self, other: &BTreeMap<K, V>) -> bool {
        self.len == other.len() && self.iter().eq(other.iter())
    }
}
impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for PersistentMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_updates_and_order_match_btree_for_every_key_type() {
        fn check<K: StateKey + fmt::Debug>(keys: Vec<K>) {
            let mut map = PersistentMap::new();
            let mut oracle = BTreeMap::new();
            let mut snapshots = Vec::new();
            for (n, key) in keys.iter().enumerate() {
                snapshots.push((map.clone(), oracle.clone()));
                map.insert(key.clone(), n);
                oracle.insert(key.clone(), n);
                *map.get_mut(key).unwrap() += 1;
                *oracle.get_mut(key).unwrap() += 1;
                assert_eq!(map, oracle);
                assert_eq!(map.get(key), oracle.get(key));
            }
            for (old, expected) in snapshots {
                assert_eq!(old, expected);
            }
        }
        let keys: Vec<u64> = (0..300u64)
            .map(|n| n.wrapping_mul(0x9e3779b97f4a7c15))
            .chain([0, u64::MAX, 7, 0])
            .collect();
        check(keys.clone());
        check(
            keys.iter()
                .map(|n| {
                    let mut key = [0; 32];
                    key[24..].copy_from_slice(&n.to_be_bytes());
                    key
                })
                .collect(),
        );
        check(
            keys.iter()
                .map(|n| ([(*n % 3) as u8; 32], [(*n % 251) as u8; 32]))
                .collect(),
        );
    }

    #[test]
    fn fixed_width_worst_case_paths_preserve_absence_and_shared_values() {
        let mut map = PersistentMap::new();
        map.insert([0; 32], vec![7; 1024]);
        for bit in 0..256 {
            let old = map.clone();
            let mut key = [0; 32];
            key[bit / 8] = 0x80 >> (bit % 8);
            map.insert(key, vec![bit; 1024]);
            assert_eq!(map[&[0; 32]].as_ptr(), old[&[0; 32]].as_ptr());
            assert!(!old.contains_key(&key));
            assert!(old.get(&[255; 32]).is_none());
        }
        let old = map.clone();
        map.get_mut(&[0; 32]).unwrap()[0] = 9;
        assert_eq!(old[&[0; 32]][0], 7);
        assert_eq!(map[&[0; 32]][0], 9);
        assert!(map.get_mut(&[255; 32]).is_none());
    }
}
