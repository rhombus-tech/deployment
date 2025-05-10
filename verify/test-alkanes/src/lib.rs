use alkanes_runtime::runtime::AlkaneResponder;
use alkanes_runtime::storage::StoragePointer;
use alkanes_runtime::message::MessageDispatch;
use alkanes_runtime::declare_alkane;
use alkanes_support::parcel::AlkaneTransfer;
use alkanes_support::response::CallResponse;
use protorune::message::MessageContext;
use metashrew_support::index_pointer::KeyValuePointer;
use metashrew_support::compat::to_arraybuffer_layout;
use anyhow::{anyhow, Result};
use std::sync::Arc;

#[cfg(test)]
pub mod tests;

/// Constants for token identification
pub const ALKANE_TEST_TOKEN_ID: u128 = 0x0aaa;
pub const ALKANE_TEST_MINT_ID: u128 = 0x0bbb;

/// Returns a StoragePointer for the token name
fn name_pointer() -> StoragePointer {
    StoragePointer(Arc::new("/name".as_bytes().to_vec()))
}

/// Returns a StoragePointer for the token symbol
fn symbol_pointer() -> StoragePointer {
    StoragePointer(Arc::new("/symbol".as_bytes().to_vec()))
}

/// Trims a u128 value to a String by removing trailing zeros
pub fn trim(v: u128) -> String {
    String::from_utf8(
        v.to_le_bytes()
            .into_iter()
            .fold(Vec::<u8>::new(), |mut r, v| {
                if v != 0 {
                    r.push(v)
                }
                r
            }),
    )
    .unwrap_or_default()
}

/// The test alkanes contract for verification testing
#[derive(Default)]
pub struct TestAlkane(());

/// Message enum for opcode-based dispatch
#[derive(MessageDispatch)]
enum TestAlkaneMessage {
    /// Initialize the token with configuration
    #[opcode(0)]
    Initialize {
        /// Initial token units
        token_units: u128,
        /// Value per mint
        value_per_mint: u128,
        /// Maximum supply cap (0 for unlimited)
        cap: u128,
        /// Token name
        name: u128,
        /// Token symbol
        symbol: u128,
    },

    /// Mint new tokens
    #[opcode(77)]
    MintTokens,

    /// Get the token name
    #[opcode(99)]
    #[returns(String)]
    GetName,

    /// Get the token symbol
    #[opcode(100)]
    #[returns(String)]
    GetSymbol,

    /// Get the total supply
    #[opcode(101)]
    #[returns(u128)]
    GetTotalSupply,

    /// Get the maximum supply cap
    #[opcode(102)]
    #[returns(u128)]
    GetCap,

    /// Get the total minted count
    #[opcode(103)]
    #[returns(u128)]
    GetMinted,

    /// Get the value per mint
    #[opcode(104)]
    #[returns(u128)]
    GetValuePerMint,
}

/// Common token functionality
impl TestAlkane {
    /// Get the token name
    fn name(&self) -> String {
        String::from_utf8(name_pointer().get().as_ref().clone())
            .unwrap_or_default()
    }

    /// Get the token symbol
    fn symbol(&self) -> String {
        String::from_utf8(symbol_pointer().get().as_ref().clone())
            .unwrap_or_default()
    }

    /// Set the token name and symbol
    fn set_name_and_symbol(&self, name: u128, symbol: u128) {
        self.set_string_field(name_pointer(), name);
        self.set_string_field(symbol_pointer(), symbol);
    }

    /// Set a string field in storage
    fn set_string_field(&self, mut pointer: StoragePointer, v: u128) {
        pointer.set(Arc::new(trim(v).as_bytes().to_vec()));
    }

    /// Get the pointer to the total supply
    fn total_supply_pointer(&self) -> StoragePointer {
        StoragePointer(Arc::new("/totalsupply".as_bytes().to_vec()))
    }

    /// Get the total supply
    fn total_supply(&self) -> u128 {
        let bytes = self.total_supply_pointer().get().as_ref().clone();
        if bytes.len() >= 16 {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&bytes[0..16]);
            u128::from_le_bytes(buf)
        } else {
            0u128
        }
    }

    /// Set the total supply
    fn set_total_supply(&self, v: u128) {
        let mut pointer = self.total_supply_pointer();
        pointer.set(Arc::new(v.to_le_bytes().to_vec()));
    }

    /// Increase the total supply
    fn increase_total_supply(&self, v: u128) -> Result<()> {
        self.set_total_supply(
            self.total_supply().checked_add(v)
                .ok_or_else(|| anyhow!("Total supply overflow"))?,
        );
        Ok(())
    }

    /// Get the pointer to the minted counter
    fn minted_pointer(&self) -> StoragePointer {
        StoragePointer(Arc::new("/minted".as_bytes().to_vec()))
    }

    /// Get the total minted count
    fn minted(&self) -> u128 {
        let bytes = self.minted_pointer().get().as_ref().clone();
        if bytes.len() >= 16 {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&bytes[0..16]);
            u128::from_le_bytes(buf)
        } else {
            0u128
        }
    }

    /// Set the total minted count
    fn set_minted(&self, v: u128) {
        let mut pointer = self.minted_pointer();
        pointer.set(Arc::new(v.to_le_bytes().to_vec()));
    }

    /// Increment the mint counter
    fn increment_mint(&self) -> Result<()> {
        self.set_minted(
            self.minted().checked_add(1)
                .ok_or_else(|| anyhow!("Mint counter overflow"))?,
        );
        Ok(())
    }

    /// Get the pointer to the value per mint
    fn value_per_mint_pointer(&self) -> StoragePointer {
        StoragePointer(Arc::new("/value-per-mint".as_bytes().to_vec()))
    }

    /// Get the value per mint
    fn value_per_mint(&self) -> u128 {
        let bytes = self.value_per_mint_pointer().get().as_ref().clone();
        if bytes.len() >= 16 {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&bytes[0..16]);
            u128::from_le_bytes(buf)
        } else {
            0u128
        }
    }

    /// Set the value per mint
    fn set_value_per_mint(&self, v: u128) {
        let mut pointer = self.value_per_mint_pointer();
        pointer.set(Arc::new(v.to_le_bytes().to_vec()));
    }

    /// Get the pointer to the supply cap
    fn cap_pointer(&self) -> StoragePointer {
        StoragePointer(Arc::new("/cap".as_bytes().to_vec()))
    }

    /// Get the supply cap
    fn cap(&self) -> u128 {
        let bytes = self.cap_pointer().get().as_ref().clone();
        if bytes.len() >= 16 {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&bytes[0..16]);
            u128::from_le_bytes(buf)
        } else {
            0u128
        }
    }

    /// Set the supply cap (0 means unlimited)
    fn set_cap(&self, v: u128) {
        let val = if v == 0 { u128::MAX } else { v };
        let mut pointer = self.cap_pointer();
        pointer.set(Arc::new(val.to_le_bytes().to_vec()));
    }

    /// Get the pointer to the initialized flag
    fn initialized_pointer(&self) -> StoragePointer {
        StoragePointer(Arc::new("/initialized".as_bytes().to_vec()))
    }

    /// Check if the contract is initialized
    fn is_initialized(&self) -> bool {
        let bytes = self.initialized_pointer().get().as_ref().clone();
        if !bytes.is_empty() {
            bytes[0] == 1
        } else {
            false
        }
    }

    /// Set the initialized flag
    fn set_initialized(&self) {
        let mut pointer = self.initialized_pointer();
        pointer.set(Arc::new(vec![1u8]));
    }

    /// Initialize the token with configuration
    fn initialize(
        &self,
        token_units: u128,
        value_per_mint: u128,
        cap: u128,
        name: u128,
        symbol: u128,
    ) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        // Prevent multiple initializations
        if self.is_initialized() {
            return Err(anyhow!("Contract already initialized"));
        }

        // Set configuration
        self.set_value_per_mint(value_per_mint);
        self.set_cap(cap);
        self.set_name_and_symbol(name, symbol);
        self.set_initialized();

        // Mint initial tokens
        if token_units > 0 {
            self.increase_total_supply(token_units)?;
            response.alkanes.0.push(AlkaneTransfer {
                id: context.myself.clone(),
                value: token_units,
            });
        }

        Ok(response)
    }

    /// Mint new tokens
    fn mint_tokens(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        // Check if contract is initialized
        if !self.is_initialized() {
            return Err(anyhow!("Contract not initialized"));
        }

        // Check if minting would exceed cap
        if self.minted() >= self.cap() {
            return Err(anyhow!(
                "Supply cap reached: {} of {}",
                self.minted(),
                self.cap()
            ));
        }

        // Mint tokens
        let value = self.value_per_mint();
        self.increase_total_supply(value)?;
        response.alkanes.0.push(AlkaneTransfer {
            id: context.myself.clone(),
            value,
        });

        // Increment mint counter
        self.increment_mint()?;

        Ok(response)
    }

    /// Get the token name
    fn get_name(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = self.name().into_bytes();

        Ok(response)
    }

    /// Get the token symbol
    fn get_symbol(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = self.symbol().into_bytes();

        Ok(response)
    }

    /// Get the total supply
    fn get_total_supply(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = self.total_supply().to_le_bytes().to_vec();

        Ok(response)
    }

    /// Get the maximum supply cap
    fn get_cap(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = self.cap().to_le_bytes().to_vec();

        Ok(response)
    }

    /// Get the total minted count
    fn get_minted(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = self.minted().to_le_bytes().to_vec();

        Ok(response)
    }

    /// Get the value per mint
    fn get_value_per_mint(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);

        response.data = self.value_per_mint().to_le_bytes().to_vec();

        Ok(response)
    }
}

impl AlkaneResponder for TestAlkane {}

// Use the MessageDispatch macro for opcode handling
declare_alkane! {
    impl AlkaneResponder for TestAlkane {
        type Message = TestAlkaneMessage;
    }
}
