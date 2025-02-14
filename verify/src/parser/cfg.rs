use std::collections::{HashMap, HashSet};
use walrus::{Function, FunctionKind};
use walrus::ir::{Instr, InstrLocId};
use anyhow::Result;

/// Represents a basic block in the control flow graph
#[derive(Debug)]
pub struct BasicBlock {
    /// Unique identifier for this block
    pub id: usize,
    /// Instructions in this block with their locations
    pub instructions: Vec<(Instr, InstrLocId)>,
    /// Successor block IDs
    pub successors: HashSet<usize>,
    /// Predecessor block IDs
    pub predecessors: HashSet<usize>,
}

impl BasicBlock {
    pub fn new(id: usize) -> Self {
        Self {
            id,
            instructions: Vec::new(),
            successors: HashSet::new(),
            predecessors: HashSet::new(),
        }
    }

    pub fn add_successor(&mut self, id: usize) {
        self.successors.insert(id);
    }

    pub fn add_predecessor(&mut self, id: usize) {
        self.predecessors.insert(id);
    }

    pub fn add_instruction(&mut self, instr: &Instr, loc: InstrLocId) {
        self.instructions.push((instr.clone(), loc));
    }

    pub fn get_instruction_ref<'a>(&'a self, index: usize) -> &'a Instr {
        &self.instructions[index].0
    }

    pub fn instruction_refs<'a>(&'a self) -> impl Iterator<Item = &'a Instr> {
        self.instructions.iter().map(|(instr, _)| instr)
    }

    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}

/// Control flow graph representation
#[derive(Debug)]
pub struct ControlFlowGraph {
    /// Map of block ID to basic blocks
    blocks: HashMap<usize, BasicBlock>,
    /// Entry block ID
    entry: usize,
    /// Exit block IDs
    exits: HashSet<usize>,
    /// Current block ID counter
    next_id: usize,
}

impl ControlFlowGraph {
    fn process_instruction(&self, instr: &Instr, block_id: usize, seq_to_block: &mut HashMap<usize, usize>) {
        match instr {
            Instr::Block(_block_instr) => {
                seq_to_block.insert(_block_instr.seq.index(), block_id);
            }
            Instr::Loop(loop_instr) => {
                seq_to_block.insert(loop_instr.seq.index(), block_id);
            }
            Instr::BrIf(br) => {
                seq_to_block.insert(br.block.index(), block_id);
            }
            _ => {}
        }
    }

    fn process_edges(&self, instr: &Instr, block_id: usize, seq_to_block: &HashMap<usize, usize>) -> (Vec<(usize, usize)>, bool) {
        let mut edges = Vec::new();
        let mut is_exit = false;

        match instr {
            Instr::Block(_block_instr) => {
                // Edges are handled in first pass
            }
            Instr::Loop(loop_instr) => {
                if let Some(&target) = seq_to_block.get(&loop_instr.seq.index()) {
                    edges.push((block_id, target));  // Enter loop
                    edges.push((target, block_id));  // Back edge
                }
            }
            Instr::BrIf(br) => {
                if let Some(&target) = seq_to_block.get(&br.block.index()) {
                    edges.push((block_id, target));  // Branch edge
                    edges.push((block_id, block_id + 1));  // Fall-through edge
                }
            }
            Instr::Return(_) => {
                is_exit = true;
            }
            _ => {}
        }
        
        (edges, is_exit)
    }

    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            entry: 0,
            exits: HashSet::new(),
            next_id: 0,
        }
    }

    /// Create a new basic block and return its ID
    pub fn create_block(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.blocks.insert(id, BasicBlock::new(id));
        id
    }

    /// Add an edge between two blocks
    pub fn add_edge(&mut self, from: usize, to: usize) {
        if let Some(block) = self.blocks.get_mut(&from) {
            block.add_successor(to);
        }
        if let Some(block) = self.blocks.get_mut(&to) {
            block.add_predecessor(from);
        }
    }

    /// Set the entry block
    pub fn set_entry(&mut self, id: usize) {
        self.entry = id;
    }

    /// Add an exit block
    pub fn add_exit(&mut self, id: usize) {
        self.exits.insert(id);
    }

    /// Build CFG from a function
    pub fn from_function(func: &Function) -> Result<Self> {
        match &func.kind {
            FunctionKind::Local(local) => {
                let mut cfg = ControlFlowGraph::new();
                let mut seq_to_block = HashMap::new();
                
                // Create entry block
                let block_id = cfg.create_block();
                cfg.set_entry(block_id);
                
                // Get instructions from the function
                let entry_block_id = local.entry_block();
                let block = local.block(entry_block_id);
                
                // First pass: Process instructions for control flow and create blocks
                for (instr, _) in block.instrs.iter() {
                    if let Instr::Block(_block_instr) = instr {
                        // Create a new block for the block instruction
                        let new_block_id = cfg.create_block();
                        seq_to_block.insert(_block_instr.seq.index(), new_block_id);
                        
                        // Add edge from current block to new block
                        cfg.add_edge(block_id, new_block_id);
                        
                        // Add edge from block to next instruction for fall-through
                        cfg.add_edge(new_block_id, block_id + 1);
                    }
                }
                
                // Second pass: Process instructions for edges
                for (instr, _) in block.instrs.iter() {
                    let (edges, is_exit) = cfg.process_edges(instr, block_id, &seq_to_block);
                    for (from, to) in edges {
                        cfg.add_edge(from, to);
                    }
                    if is_exit {
                        cfg.add_exit(block_id);
                    }
                }
                
                // Third pass: Add instructions to block
                let current_block = cfg.blocks.get_mut(&block_id).unwrap();
                for (idx, (instr, _)) in block.instrs.iter().enumerate() {
                    let loc = InstrLocId::new(idx as u32);
                    current_block.add_instruction(instr, loc);
                }
                
                // Make sure we have at least one exit
                if cfg.exits.is_empty() {
                    cfg.add_exit(block_id);
                }
                
                Ok(cfg)
            }
            _ => Err(anyhow::anyhow!("Unsupported function kind")),
        }
    }

    /// Get all paths from entry to exit
    pub fn get_paths(&self) -> Vec<Vec<usize>> {
        let mut paths = Vec::new();
        let mut visited = HashSet::new();
        let mut current_path = vec![self.entry];
        
        self.dfs_paths(&mut paths, &mut visited, &mut current_path, self.entry);
        
        paths
    }

    /// DFS helper for path finding
    fn dfs_paths(
        &self,
        paths: &mut Vec<Vec<usize>>,
        visited: &mut HashSet<usize>,
        current_path: &mut Vec<usize>,
        current: usize
    ) {
        if self.exits.contains(&current) {
            paths.push(current_path.clone());
            return;
        }
        
        visited.insert(current);
        
        if let Some(block) = self.blocks.get(&current) {
            for &succ in &block.successors {
                if !visited.contains(&succ) {
                    current_path.push(succ);
                    self.dfs_paths(paths, visited, current_path, succ);
                    current_path.pop();
                }
            }
        }
        
        visited.remove(&current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wat::parse_str;
    use walrus::Module;

    #[test]
    fn test_simple_cfg() -> Result<()> {
        let wasm = parse_str(r#"
            (module
                (func (export "test") (result i32)
                    (block (result i32)
                        i32.const 42
                    )
                )
            )
        "#)?;

        let module = Module::from_buffer(&wasm)?;
        let func = module.funcs.iter().next().unwrap();
        
        let cfg = ControlFlowGraph::from_function(func)?;
        
        // Verify we have the correct number of blocks
        assert!(cfg.blocks.len() > 0);
        
        // Verify we have paths from entry to exit
        let paths = cfg.get_paths();
        assert!(!paths.is_empty());
        
        Ok(())
    }
}
