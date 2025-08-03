use std::collections::{HashMap, HashSet};

/// Control Flow Graph representation for EVM bytecode
/// This structure is essential for formal verification as it represents all possible
/// execution paths through a contract's bytecode
#[derive(Debug, Default, Clone)]
pub struct ControlFlowGraph {
    /// Jump destinations in the bytecode
    jump_destinations: HashSet<usize>,
    
    /// Basic blocks in the CFG (identified by their start PC)
    blocks: HashSet<usize>,
    
    /// Edges between basic blocks (from_block -> to_blocks)
    edges: HashMap<usize, HashSet<usize>>,
    
    /// Instruction-level mapping (PC -> opcode)
    instructions: HashMap<usize, u8>,
    
    /// Formal verification properties that have been checked
    verified_properties: HashMap<String, bool>,
}

impl ControlFlowGraph {
    /// Create a new, empty control flow graph
    pub fn new() -> Self {
        Self {
            jump_destinations: HashSet::new(),
            blocks: HashSet::new(),
            edges: HashMap::new(),
            instructions: HashMap::new(),
            verified_properties: HashMap::new(),
        }
    }
    
    /// Add a jump destination
    pub fn add_jump_destination(&mut self, pc: usize) {
        self.jump_destinations.insert(pc);
    }
    
    /// Check if a PC is a jump destination
    pub fn is_jump_destination(&self, pc: usize) -> bool {
        self.jump_destinations.contains(&pc)
    }
    
    /// Get all jump destinations
    pub fn get_jump_destinations(&self) -> Vec<usize> {
        self.jump_destinations.iter().copied().collect()
    }
    
    /// Create a new basic block starting at the given PC
    /// Returns the block ID (which is the starting PC)
    pub fn create_block(&mut self, pc: usize) -> usize {
        self.blocks.insert(pc);
        pc
    }
    
    /// Add an edge between two blocks
    pub fn add_edge(&mut self, from_block: usize, to_block: usize) {
        self.edges.entry(from_block)
            .or_insert_with(HashSet::new)
            .insert(to_block);
    }
    
    /// Get all blocks in the graph
    pub fn get_blocks(&self) -> Vec<usize> {
        self.blocks.iter().copied().collect()
    }
    
    /// Get all successors of a block
    pub fn get_successors(&self, block: usize) -> Vec<usize> {
        self.edges.get(&block)
            .map(|successors| successors.iter().copied().collect())
            .unwrap_or_default()
    }
    
    /// Record an instruction in the graph
    pub fn add_instruction(&mut self, pc: usize, opcode: u8) {
        self.instructions.insert(pc, opcode);
    }
    
    /// Record a verified property
    pub fn add_verified_property(&mut self, property_name: String, result: bool) {
        self.verified_properties.insert(property_name, result);
    }
    
    /// Check if a property has been verified
    pub fn is_property_verified(&self, property_name: &str) -> Option<bool> {
        self.verified_properties.get(property_name).copied()
    }
    
    /// Check if a path exists between two blocks
    pub fn path_exists(&self, from_block: usize, to_block: usize) -> bool {
        let mut visited = HashSet::new();
        let mut queue = vec![from_block];
        
        while let Some(current) = queue.pop() {
            if current == to_block {
                return true;
            }
            
            if visited.insert(current) {
                if let Some(successors) = self.edges.get(&current) {
                    for &successor in successors {
                        queue.push(successor);
                    }
                }
            }
        }
        
        false
    }
    
    /// Get all possible execution paths between two blocks
    /// Returns a vector of paths, where each path is a vector of block IDs
    pub fn get_paths(&self, from_block: usize, to_block: usize) -> Vec<Vec<usize>> {
        let mut paths = Vec::new();
        let mut current_path = vec![from_block];
        self.dfs_paths(from_block, to_block, &mut current_path, &mut paths);
        paths
    }
    
    /// Depth-first search to find all paths between two blocks
    fn dfs_paths(
        &self,
        current: usize,
        target: usize,
        current_path: &mut Vec<usize>,
        paths: &mut Vec<Vec<usize>>,
    ) {
        if current == target {
            paths.push(current_path.clone());
            return;
        }
        
        if let Some(successors) = self.edges.get(&current) {
            for &successor in successors {
                // Avoid cycles by checking if successor is already in the path
                if !current_path.contains(&successor) {
                    current_path.push(successor);
                    self.dfs_paths(successor, target, current_path, paths);
                    current_path.pop();
                }
            }
        }
    }
    
    /// Identify loops in the control flow graph
    pub fn find_loops(&self) -> Vec<HashSet<usize>> {
        let mut loops = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = Vec::new();
        
        // Use Tarjan's algorithm to find strongly connected components (loops)
        for &block in &self.blocks {
            if !visited.contains(&block) {
                self.find_sccs(block, &mut visited, &mut stack, &mut HashSet::new(), &mut loops);
            }
        }
        
        loops
    }
    
    /// Helper function for Tarjan's algorithm to find strongly connected components
    fn find_sccs(
        &self,
        current: usize,
        visited: &mut HashSet<usize>,
        stack: &mut Vec<usize>,
        on_stack: &mut HashSet<usize>,
        sccs: &mut Vec<HashSet<usize>>,
    ) {
        visited.insert(current);
        stack.push(current);
        on_stack.insert(current);
        
        if let Some(successors) = self.edges.get(&current) {
            for &successor in successors {
                if !visited.contains(&successor) {
                    self.find_sccs(successor, visited, stack, on_stack, sccs);
                } else if on_stack.contains(&successor) {
                    // Found a cycle
                    let mut scc = HashSet::new();
                    let mut i = stack.len() - 1;
                    loop {
                        let block = stack[i];
                        scc.insert(block);
                        if block == successor {
                            break;
                        }
                        i -= 1;
                    }
                    if scc.len() > 1 {
                        sccs.push(scc);
                    }
                }
            }
        }
        
        // Remove from stack
        if on_stack.contains(&current) {
            let idx = stack.iter().position(|&x| x == current).unwrap();
            stack.remove(idx);
            on_stack.remove(&current);
        }
    }
}

/// Formal verification proof for a property of the bytecode
#[derive(Debug, Clone)]
pub struct FormalVerificationProof {
    /// Name of the property that was verified
    pub property_name: String,
    
    /// Whether the property holds (true) or can be violated (false)
    pub property_holds: bool,
    
    /// Counter-example path if property doesn't hold
    pub counter_example: Option<Vec<usize>>,
    
    /// Formal verification method used
    pub method: String,
    
    /// Proof hash (cryptographic commitment to the proof)
    pub proof_hash: String,
}

impl FormalVerificationProof {
    /// Create a new proof for a verified property
    pub fn new(property_name: String, property_holds: bool) -> Self {
        Self {
            property_name,
            property_holds,
            counter_example: None,
            method: "bytecode-level formal verification".to_string(),
            proof_hash: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        }
    }
    
    /// Add a counter-example to the proof
    pub fn with_counter_example(mut self, counter_example: Vec<usize>) -> Self {
        self.counter_example = Some(counter_example);
        self
    }
    
    /// Set the verification method used
    pub fn with_method(mut self, method: String) -> Self {
        self.method = method;
        self
    }
    
    /// Generate a cryptographic hash for the proof
    pub fn with_proof_hash(mut self, proof_hash: String) -> Self {
        self.proof_hash = proof_hash;
        self
    }
}
