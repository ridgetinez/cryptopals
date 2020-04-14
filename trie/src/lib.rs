pub struct Trie {
    chr: char,
    has: bool,
    children: Vec<Trie>,
}

impl Trie {
    pub fn new() -> Self {
        Trie {
            chr: 'a',
            has: false,
            children: vec![]
        }
    }

    pub fn insert(&mut self, word: &str) {
        if word.is_empty() {
            self.has = true
        } else {
            let nextchar = word.chars().nth(0).unwrap();
            let mut nextnode = self.children.iter_mut().find(|t| t.chr == nextchar);
            match nextnode {
                None => {
                    let mut nextnode = Trie {
                        chr: nextchar,
                        has: false,
                        children: vec![]
                    };
                    nextnode.insert(&word.chars().skip(1).collect::<String>());
                    self.children.push(nextnode)
                },
                Some(node) => {
                    node.insert(&word.chars().skip(1).collect::<String>())
                }
            }
        }
    }

    // Maintain invariant that we visit a node without the character it matched on
    // This is so we can add the epsilon node as the root trie.
    // Currently does not handle anything outside of u8, some internal fragmentation!
    pub fn contains(&self, word: &str) -> bool {
        if word.is_empty() {
            return self.has
        }
        for tnode in self.children.iter() {
            if tnode.chr == word.chars().nth(0).unwrap() {
                return tnode.contains(&word.chars().skip(1).collect::<String>())
            }
        }
        false
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_epsilon() {
        let t = Trie {
            chr: 'e',
            has: true,
            children: vec![Trie {
                chr: 'a',
                has: true,
                children: vec![],
            }],
        };
        assert_eq!(t.contains(""), true)
    }

    #[test]
    fn insert_then_contains() {
        let mut t = Trie::new();
        t.insert("hello");
        assert_eq!(t.contains("hello"), true);
        assert_eq!(t.contains("hell"), false);
        assert_eq!(t.contains("hel"), false);
        assert_eq!(t.contains("he"), false);
        assert_eq!(t.contains("h"), false);
        assert_eq!(t.contains(""), false);
        assert_eq!(t.contains("helper"), false);
        assert_eq!(t.contains("awdhbdwabadbahwdb"), false);
    }

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
