//! StatelessVM integration module
//! Provides functionality for interacting with Avalanche's StatelessVM

mod client;
#[cfg(test)]
mod tests;

pub use client::StatelessVmClient;
