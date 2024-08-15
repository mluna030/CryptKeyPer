use crate::hash_function::Sha256HashFunction;

pub struct MerkleTree {
    pub leaves: Vec<[u8; 32]>,
    pub tree: Vec<Vec<[u8; 32]>>,
    pub root: Option<[u8; 32]>,
}

impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Self {
        let mut tree = vec![leaves.clone()];
        let mut current_layer = leaves.clone();

        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();

            for i in (0..current_layer.len()).step_by(2) {
                let combined = if i + 1 < current_layer.len() {
                    [current_layer[i].as_ref(), current_layer[i + 1].as_ref()].concat()
                } else {
                    current_layer[i].to_vec()
                };

                let hashed = Sha256HashFunction::hash(&combined);
                next_layer.push(hashed);
            }

            tree.push(next_layer.clone());
            current_layer = next_layer;
        }

        let root = current_layer.first().cloned();

        MerkleTree {
            leaves,
            tree,
            root,
        }
    }

    pub fn get_auth_path(&self, index: usize) -> Vec<[u8; 32]> {
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

    pub fn update_leaf(&mut self, index: usize, new_leaf: [u8; 32]) {
        self.leaves[index] = new_leaf;
        self.recompute_tree();
    }

    fn recompute_tree(&mut self) {
        let mut current_layer = self.leaves.clone();
        self.tree = vec![current_layer.clone()];

        while current_layer.len() > 1 {
            let mut next_layer = Vec::new();

            for i in (0..current_layer.len()).step_by(2) {
                let combined = if i + 1 < current_layer.len() {
                    [current_layer[i].as_ref(), current_layer[i + 1].as_ref()].concat()
                } else {
                    current_layer[i].to_vec()
                };

                let hashed = Sha256HashFunction::hash(&combined);
                next_layer.push(hashed);
            }

            self.tree.push(next_layer.clone());
            current_layer = next_layer;
        }

        self.root = current_layer.first().cloned();
    }
}
