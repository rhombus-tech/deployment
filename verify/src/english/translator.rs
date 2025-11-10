// LLM Translator - Converts English contracts to Rust code
use super::EnglishContract;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;

pub struct LLMTranslator {
    api_key: String,
    model: String,
    client: reqwest::Client,
}

#[derive(Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    temperature: f32,
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ClaudeResponse {
    content: Vec<Content>,
}

#[derive(Deserialize)]
struct Content {
    text: String,
}

impl LLMTranslator {
    pub fn new() -> Result<Self> {
        // Load .env file if it exists
        let _ = dotenv::dotenv();
        
        let api_key = env::var("ANTHROPIC_API_KEY")
            .or_else(|_| env::var("OPENAI_API_KEY"))
            .context("No API key found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY")?;
        
        // Use Claude 3 Haiku - fast, available, and good for code generation
        let model = "claude-3-haiku-20240307".to_string();
        
        Ok(Self {
            api_key,
            model,
            client: reqwest::Client::new(),
        })
    }
    
    pub async fn translate_to_rust(&self, contract: &EnglishContract) -> Result<String> {
        let prompt = self.build_prompt(contract);
        let rust_code = self.call_llm(&prompt).await?;
        let cleaned_code = self.extract_rust_code(&rust_code);
        self.validate_rust_code(&cleaned_code)?;
        Ok(cleaned_code)
    }
    
    fn build_prompt(&self, contract: &EnglishContract) -> String {
        format!(
            r#"Generate production-ready standalone Rust WASM contract code.

CRITICAL REQUIREMENTS:
1. Each function must be a standalone #[no_mangle] pub extern "C" fn
2. Functions take raw parameters (*const u8, i32 length) and return Vec<u8>
3. NO env:: calls - this is bare WASM with no runtime
4. Use borsh for serialization only
5. All state is passed as parameters
6. Return empty Vec on error, never panic

EXAMPLE STRUCTURE:
```rust
use borsh::{{BorshDeserialize, BorshSerialize}};

#[derive(BorshSerialize, BorshDeserialize)]
struct State {{
    // fields
}}

#[no_mangle]
pub extern "C" fn function_name() -> Vec<u8> {{
    // Implementation that returns serialized result
    Vec::new()
}}
```

CONTRACT: {}
DESCRIPTION: {}
STATE VARIABLES: {:?}
FUNCTIONS: {:?}

Generate ONLY the Rust code. No explanations. Must compile."#,
            contract.name, contract.description, contract.state, contract.functions
        )
    }
    
    async fn call_llm(&self, prompt: &str) -> Result<String> {
        let request = ClaudeRequest {
            model: self.model.clone(),
            max_tokens: 4096, // Max for Claude 3 Haiku
            temperature: 0.2,
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };
        
        let response = self.client
            .post("https://api.anthropic.com/v1/messages")
            .header("Content-Type", "application/json")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&request)
            .send()
            .await?;
        
        if !response.status().is_success() {
            anyhow::bail!("API error: {}", response.text().await?);
        }
        
        let claude_response: ClaudeResponse = response.json().await?;
        claude_response.content.first()
            .map(|c| c.text.clone())
            .context("Empty LLM response")
    }
    
    fn extract_rust_code(&self, text: &str) -> String {
        if let Some(start) = text.find("```rust") {
            if let Some(end) = text[start + 7..].find("```") {
                return text[start + 7..start + 7 + end].trim().to_string();
            }
        }
        text.trim().to_string()
    }
    
    fn validate_rust_code(&self, code: &str) -> Result<()> {
        if !code.contains("#[no_mangle]") {
            anyhow::bail!("Missing #[no_mangle]");
        }
        if !code.contains("extern \"C\"") {
            anyhow::bail!("Missing extern \"C\"");
        }
        
        let dangerous = vec!["unsafe {", "std::fs", "std::net", "rand::"];
        for pattern in dangerous {
            if code.contains(pattern) {
                anyhow::bail!("Contains dangerous pattern: {}", pattern);
            }
        }
        
        Ok(())
    }
}
