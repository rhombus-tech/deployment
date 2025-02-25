use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::types::*;

#[cfg(test)]
mod arithmetic;
#[cfg(test)]
mod bitmask;
#[cfg(test)]
mod delegate;
#[cfg(test)]
mod reentrancy;
#[cfg(test)]
mod solidity_checks;
#[cfg(test)]
mod real_world_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    use hex_literal::hex;
    use anyhow::Result;

    #[test]
    fn test_bytecode_analyzer() -> Result<()> {
        // Basic test to ensure analyzer works
        let bytecode = Bytes::from(hex!(
            "608060405234801561001057600080fd5b50610150806100206000396000f3fe"
        ));

        let analyzer = BytecodeAnalyzer::new();

        Ok(())
    }
}
