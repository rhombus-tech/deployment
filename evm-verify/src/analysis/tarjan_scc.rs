use ethers::types::H160;
use std::collections::{HashMap, HashSet};

/// Tarjan's Strongly Connected Components algorithm
/// Finds all cycles in O(V + E) time - much better than DFS from each node
pub struct TarjanSCC {
    index: usize,
    stack: Vec<H160>,
    indices: HashMap<H160, usize>,
    lowlinks: HashMap<H160, usize>,
    on_stack: HashSet<H160>,
    sccs: Vec<Vec<H160>>,
}

impl TarjanSCC {
    pub fn new() -> Self {
        Self {
            index: 0,
            stack: Vec::new(),
            indices: HashMap::new(),
            lowlinks: HashMap::new(),
            on_stack: HashSet::new(),
            sccs: Vec::new(),
        }
    }

    /// Find all strongly connected components (cycles) in the graph
    /// Returns components with > 1 node (actual cycles)
    pub fn find_sccs(
        &mut self,
        adjacency: &HashMap<H160, Vec<H160>>,
    ) -> Vec<Vec<H160>> {
        // Run Tarjan's algorithm from each unvisited node
        let nodes: Vec<H160> = adjacency.keys().copied().collect();
        
        for node in nodes {
            if !self.indices.contains_key(&node) {
                self.strongconnect(node, adjacency);
            }
        }

        // Return only SCCs with more than 1 node (actual cycles)
        self.sccs
            .iter()
            .filter(|scc| scc.len() > 1)
            .cloned()
            .collect()
    }

    fn strongconnect(
        &mut self,
        v: H160,
        adjacency: &HashMap<H160, Vec<H160>>,
    ) {
        // Set the depth index for v to the smallest unused index
        self.indices.insert(v, self.index);
        self.lowlinks.insert(v, self.index);
        self.index += 1;
        self.stack.push(v);
        self.on_stack.insert(v);

        // Consider successors of v
        if let Some(neighbors) = adjacency.get(&v) {
            for &w in neighbors {
                if !self.indices.contains_key(&w) {
                    // Successor w has not yet been visited; recurse on it
                    self.strongconnect(w, adjacency);
                    let w_lowlink = *self.lowlinks.get(&w).unwrap();
                    let v_lowlink = *self.lowlinks.get(&v).unwrap();
                    self.lowlinks.insert(v, v_lowlink.min(w_lowlink));
                } else if self.on_stack.contains(&w) {
                    // Successor w is in stack S and hence in the current SCC
                    let w_index = *self.indices.get(&w).unwrap();
                    let v_lowlink = *self.lowlinks.get(&v).unwrap();
                    self.lowlinks.insert(v, v_lowlink.min(w_index));
                }
            }
        }

        // If v is a root node, pop the stack and generate an SCC
        let v_lowlink = *self.lowlinks.get(&v).unwrap();
        let v_index = *self.indices.get(&v).unwrap();
        
        if v_lowlink == v_index {
            let mut scc = Vec::new();
            loop {
                if let Some(w) = self.stack.pop() {
                    self.on_stack.remove(&w);
                    scc.push(w);
                    if w == v {
                        break;
                    }
                } else {
                    break;
                }
            }
            self.sccs.push(scc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::H160;

    #[test]
    fn test_tarjan_simple_cycle() {
        let mut adjacency = HashMap::new();
        let a = H160::from_low_u64_be(1);
        let b = H160::from_low_u64_be(2);
        let c = H160::from_low_u64_be(3);

        // Create cycle: A -> B -> C -> A
        adjacency.insert(a, vec![b]);
        adjacency.insert(b, vec![c]);
        adjacency.insert(c, vec![a]);

        let mut tarjan = TarjanSCC::new();
        let cycles = tarjan.find_sccs(&adjacency);

        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].len(), 3);
    }

    #[test]
    fn test_tarjan_no_cycle() {
        let mut adjacency = HashMap::new();
        let a = H160::from_low_u64_be(1);
        let b = H160::from_low_u64_be(2);
        let c = H160::from_low_u64_be(3);

        // Create DAG: A -> B -> C
        adjacency.insert(a, vec![b]);
        adjacency.insert(b, vec![c]);
        adjacency.insert(c, vec![]);

        let mut tarjan = TarjanSCC::new();
        let cycles = tarjan.find_sccs(&adjacency);

        assert_eq!(cycles.len(), 0); // No cycles
    }

    #[test]
    fn test_tarjan_multiple_cycles() {
        let mut adjacency = HashMap::new();
        let a = H160::from_low_u64_be(1);
        let b = H160::from_low_u64_be(2);
        let c = H160::from_low_u64_be(3);
        let d = H160::from_low_u64_be(4);

        // Create two cycles: A <-> B and C <-> D
        adjacency.insert(a, vec![b]);
        adjacency.insert(b, vec![a]);
        adjacency.insert(c, vec![d]);
        adjacency.insert(d, vec![c]);

        let mut tarjan = TarjanSCC::new();
        let cycles = tarjan.find_sccs(&adjacency);

        assert_eq!(cycles.len(), 2);
    }
}
