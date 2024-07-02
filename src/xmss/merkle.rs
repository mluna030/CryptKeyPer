use crate::hash_function::Sha256HashFunction;

pub struct MerkleTree {
    pub leaves: Vec<String>,
    pub tree: Vec<Vec<String>>,
    pub root: String,
}

impl MerkleTree {
    pub fn new(leaves: Vec<String>) -> Self {
        let mut tree = vec![leaves.clone()];
        let mut current_layer = leaves.clone();

        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();

            for i in (0..current_layer.len()).step_by(2) {
                let combined = if i + 1 < current_layer.len() {
                    format!("{}{}", current_layer[i], current_layer[i + 1])
                } else {
                    current_layer[i].clone()
                };

                let hashed = Sha256HashFunction::hash_hex(combined.as_bytes());
                next_layer.push(hashed);
            }

            tree.push(next_layer.clone());
            current_layer = next_layer;
        }

        let root = current_layer.first().cloned().unwrap_or_default();

        MerkleTree {
            leaves,
            tree,
            root,
        }
    }

    pub fn get_auth_path(&self, index: usize) -> Vec<String> {
        let mut path = Vec::new();
        let mut idx = index;

        for layer in &self.tree {
            if idx % 2 == 0 && idx + 1 < layer.len() {
                path.push(layer[idx + 1].clone());
            } else if idx % 2 == 1 {
                path.push(layer[idx - 1].clone());
            }
            idx /= 2;
        }
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let leaves = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        let tree = MerkleTree::new(leaves);
        let expected_root_hash = "12a40550c10c6339bf6f271445270e49b844d6c9e8abc36b9b642be532befe94";  // Replace with actual expected hash
        assert_eq!(tree.root, expected_root_hash);
    }
}
