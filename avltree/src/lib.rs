use std::fmt::{Display, Debug};
use std::cmp::Ordering;
use std::iter::FromIterator;

// Exercise 1: Define the datatypes as enums, different from the struct they use!
// Ord is overly strict, we only need `lt`, not `lte`

#[derive(Debug, PartialEq, Eq, Clone)]
enum BinaryTree<T> {
    Leaf,
    Node(T, Box<BinaryTree<T>>, Box<BinaryTree<T>>),
}

#[derive(Debug)]
struct BinaryTreeInOrderIter<'a,T> {
    prev_nodes: Vec<&'a BinaryTree<T>>,
    current_tree: &'a BinaryTree<T>,
}

impl<'a, T: Debug + Display + PartialOrd> BinaryTree<T> {
    pub fn new() -> Self {
        BinaryTree::Leaf
    }

    pub fn insert(&mut self, data: T) {
        match self {
            BinaryTree::Leaf => *self = BinaryTree::new_node(data),
            BinaryTree::Node(x,l,r) => match (*x).partial_cmp(&data).unwrap() {
                Ordering::Greater => l.insert(data),
                Ordering::Less => r.insert(data),
                Ordering::Equal => (),
            },
        }
    }

    pub fn iter(&'a self) -> BinaryTreeInOrderIter<'a, T> {
        BinaryTreeInOrderIter {
            prev_nodes: Vec::new(),
            current_tree: &self,
        }
    }

    fn new_node(data: T) -> BinaryTree<T> {
        BinaryTree::Node(data, Box::new(BinaryTree::Leaf), Box::new(BinaryTree::Leaf))
    }
}

impl<T: PartialOrd + Display + Debug> FromIterator<T> for BinaryTree<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut tree = Self::new();

        for v in iter {
            tree.insert(v);
        }
        
        tree
    }
}

impl<'a, T: 'a + PartialOrd + Debug> Iterator for BinaryTreeInOrderIter<'a,T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.current_tree {
                BinaryTree::Leaf => {
                    match self.prev_nodes.pop() {
                        None => return None,
                        Some(node) => match node {
                            BinaryTree::Leaf => unreachable![],
                            BinaryTree::Node(x,l,r) => {
                                self.current_tree = r;
                                return Some(x)
                            },
                        }
                    }
                },
                BinaryTree::Node(x0,l0,r0) => {
                    if let BinaryTree::Node(x1,l1,r1) = &**l0 {
                        // put back to visit the right hand side
                        self.prev_nodes.push(self.current_tree);
                        self.current_tree = l0;
                        continue
                    }
                    if let BinaryTree::Node(x1,l1,r1) = &**r0 {
                        self.current_tree = r0;
                        return Some(x0);
                    }

                    self.current_tree = &BinaryTree::Leaf;
                    return Some(x0);
                },
            }
        }
    }
}

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[cfg(test)]
mod properties {
    use super::*;
    use std::collections::BTreeSet;

    #[quickcheck]
    fn iterator_parity(mut xs: Vec<usize>) -> bool {
        let bst_set = xs.iter().cloned().collect::<BinaryTree<_>>();
        let btree_set = xs.iter().cloned().collect::<BTreeSet<_>>();
        bst_set.iter().zip(btree_set.iter()).all(|(a,b)| a == b) && bst_set.iter().count() == btree_set.iter().count()
    }
}
