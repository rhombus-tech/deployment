use evm_verify::state_trie::mpt::MerklePatriciaTrie;
use ethers::types::Bytes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing basic MPT functionality...");
    
    // Create a new MPT
    let mut mpt = MerklePatriciaTrie::new();
    println!("✓ Created new MPT with root: {:?}", mpt.root());
    
    // Test insertion
    let key1 = b"hello";
    let value1 = Bytes::from("world".as_bytes().to_vec());
    
    mpt.insert(key1, value1.clone()).await?;
    println!("✓ Inserted key-value pair: {:?} -> {:?}", String::from_utf8_lossy(key1), value1);
    println!("  New root: {:?}", mpt.root());
    
    // Test retrieval
    let retrieved = mpt.get(key1).await?;
    match retrieved {
        Some(val) if val == value1 => {
            println!("✓ Successfully retrieved value: {:?}", val);
        },
        Some(val) => {
            println!("✗ Retrieved value mismatch: expected {:?}, got {:?}", value1, val);
        },
        None => {
            println!("✗ Value not found for key: {:?}", String::from_utf8_lossy(key1));
        }
    }
    
    // Test multiple insertions
    let key2 = b"ethereum";
    let value2 = Bytes::from("blockchain".as_bytes().to_vec());
    
    mpt.insert(key2, value2.clone()).await?;
    println!("✓ Inserted second key-value pair: {:?} -> {:?}", String::from_utf8_lossy(key2), value2);
    println!("  New root: {:?}", mpt.root());
    
    // Verify both values can be retrieved
    let retrieved1 = mpt.get(key1).await?;
    let retrieved2 = mpt.get(key2).await?;
    
    if retrieved1 == Some(value1.clone()) && retrieved2 == Some(value2.clone()) {
        println!("✓ Both values successfully retrieved after multiple insertions");
    } else {
        println!("✗ Issues with retrieval after multiple insertions");
    }
    
    println!("\n🎉 Basic MPT functionality test completed!");
    
    Ok(())
}
