/// AI Explanation Layer for Security Findings
///
/// This module provides AI-generated explanations for cryptographically proven vulnerabilities.
/// IMPORTANT: AI does NOT detect vulnerabilities - it only explains them.

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// AI-generated explanation for a vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIExplanation {
    /// Disclaimer that this is AI-generated
    pub ai_generated: bool,
    
    /// Plain English explanation of what the vulnerability is
    pub plain_english: String,
    
    /// Business impact and estimated financial risk
    pub business_impact: String,
    
    /// Specific code-level fix suggestions
    pub fix_suggestion: String,
    
    /// References to similar historical exploits
    pub similar_exploits: Vec<ExploitReference>,
    
    /// Quality confidence of the explanation (NOT detection confidence)
    pub explanation_quality: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitReference {
    pub name: String,
    pub date: String,
    pub loss_amount: String,
    pub similarity: String,
}

/// Configuration for AI explainer
#[derive(Debug, Clone)]
pub struct AIExplainerConfig {
    /// OpenAI API key
    pub api_key: Option<String>,
    
    /// Model to use (gpt-4o, gpt-4-turbo, claude-3-5-sonnet)
    pub model: String,
    
    /// Temperature (0.1 for deterministic)
    pub temperature: f64,
    
    /// Enable caching
    pub enable_cache: bool,
    
    /// Use batch processing
    pub use_batching: bool,
}

impl Default for AIExplainerConfig {
    fn default() -> Self {
        Self {
            api_key: std::env::var("OPENAI_API_KEY").ok(),
            model: "gpt-4o".to_string(),
            temperature: 0.1,
            enable_cache: true,
            use_batching: true,
        }
    }
}

/// AI Explainer service
pub struct AIExplainer {
    config: AIExplainerConfig,
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, AIExplanation>>>,
}

impl AIExplainer {
    pub fn new(config: AIExplainerConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Explain a single vulnerability
    pub async fn explain_vulnerability(
        &self,
        warning: &SecurityWarning,
    ) -> Result<AIExplanation> {
        // Check cache first
        let cache_key = format!("{:?}_{}", warning.kind, warning.severity);
        
        if self.config.enable_cache {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }
        
        // Generate explanation
        let explanation = self.generate_explanation(warning).await?;
        
        // Cache it
        if self.config.enable_cache {
            let mut cache = self.cache.write().await;
            cache.insert(cache_key, explanation.clone());
        }
        
        Ok(explanation)
    }
    
    /// Explain multiple vulnerabilities in batch (faster + cheaper)
    pub async fn explain_vulnerabilities_batch(
        &self,
        warnings: &[SecurityWarning],
    ) -> Result<Vec<AIExplanation>> {
        if warnings.is_empty() {
            return Ok(Vec::new());
        }
        
        if !self.config.use_batching || warnings.len() == 1 {
            // Process individually
            let mut results = Vec::new();
            for warning in warnings {
                results.push(self.explain_vulnerability(warning).await?);
            }
            return Ok(results);
        }
        
        // Batch process all vulnerabilities in one API call
        self.generate_explanations_batch(warnings).await
    }
    
    async fn generate_explanation(&self, warning: &SecurityWarning) -> Result<AIExplanation> {
        let api_key = self.config.api_key.as_ref()
            .context("OpenAI API key not configured")?;
        
        let prompt = self.build_prompt(warning);
        
        let response = self.client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&serde_json::json!({
                "model": self.config.model,
                "messages": [{
                    "role": "system",
                    "content": SYSTEM_PROMPT
                }, {
                    "role": "user",
                    "content": prompt
                }],
                "temperature": self.config.temperature,
                "response_format": { "type": "json_object" }
            }))
            .send()
            .await?;
            
        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("OpenAI API error: {}", error_text);
        }
        
        let response_json: serde_json::Value = response.json().await?;
        let content = response_json["choices"][0]["message"]["content"]
            .as_str()
            .context("Missing content in response")?;
            
        let explanation: AIExplanationResponse = serde_json::from_str(content)?;
        
        Ok(AIExplanation {
            ai_generated: true,
            plain_english: explanation.plain_english,
            business_impact: explanation.business_impact,
            fix_suggestion: explanation.fix_suggestion,
            similar_exploits: explanation.similar_exploits,
            explanation_quality: 0.9, // High quality from GPT-4
        })
    }
    
    async fn generate_explanations_batch(&self, warnings: &[SecurityWarning]) -> Result<Vec<AIExplanation>> {
        let api_key = self.config.api_key.as_ref()
            .context("OpenAI API key not configured")?;
        
        let prompt = self.build_batch_prompt(warnings);
        
        let response = self.client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&serde_json::json!({
                "model": self.config.model,
                "messages": [{
                    "role": "system",
                    "content": SYSTEM_PROMPT
                }, {
                    "role": "user",
                    "content": prompt
                }],
                "temperature": self.config.temperature,
                "response_format": { "type": "json_object" }
            }))
            .send()
            .await?;
            
        let response_json: serde_json::Value = response.json().await?;
        let content = response_json["choices"][0]["message"]["content"]
            .as_str()
            .context("Missing content in response")?;
            
        let batch_response: BatchExplanationResponse = serde_json::from_str(content)?;
        
        Ok(batch_response.explanations.into_iter().map(|e| AIExplanation {
            ai_generated: true,
            plain_english: e.plain_english,
            business_impact: e.business_impact,
            fix_suggestion: e.fix_suggestion,
            similar_exploits: e.similar_exploits,
            explanation_quality: 0.9,
        }).collect())
    }
    
    fn build_prompt(&self, warning: &SecurityWarning) -> String {
        format!(r#"
You are a security expert explaining smart contract vulnerabilities to developers and auditors.

CRYPTOGRAPHICALLY PROVEN VULNERABILITY:
- Type: {:?}
- Severity: {:?}
- Description: {}
- Remediation: {}

This vulnerability has been MATHEMATICALLY PROVEN to exist through cryptographic analysis.
Your job is to EXPLAIN it clearly, not detect it (detection is already done).

PROVIDE:
1. plain_english: Explain what this vulnerability is in simple terms (3-4 sentences)
2. business_impact: Explain the financial and business risk with specific $ estimates if possible
3. fix_suggestion: Provide actual code snippets showing how to fix this
4. similar_exploits: List 2-3 real historical exploits similar to this with dates and amounts

Format as JSON matching this schema:
{{
  "plain_english": "string",
  "business_impact": "string", 
  "fix_suggestion": "string",
  "similar_exploits": [
    {{"name": "string", "date": "string", "loss_amount": "string", "similarity": "string"}}
  ]
}}
"#, warning.kind, warning.severity, warning.description, warning.remediation)
    }
    
    fn build_batch_prompt(&self, warnings: &[SecurityWarning]) -> String {
        let vulnerabilities: Vec<String> = warnings.iter().enumerate().map(|(i, w)| {
            format!("{}. {:?} ({}): {}", i+1, w.kind, w.severity, w.description)
        }).collect();
        
        format!(r#"
You are a security expert explaining smart contract vulnerabilities.

CRYPTOGRAPHICALLY PROVEN VULNERABILITIES:
{}

These vulnerabilities have been MATHEMATICALLY PROVEN to exist.
Explain each one clearly.

Format as JSON:
{{
  "explanations": [
    {{
      "plain_english": "string",
      "business_impact": "string",
      "fix_suggestion": "string",
      "similar_exploits": [{{"name": "string", "date": "string", "loss_amount": "string", "similarity": "string"}}]
    }}
  ]
}}
"#, vulnerabilities.join("\n"))
    }
}

#[derive(Deserialize)]
struct AIExplanationResponse {
    plain_english: String,
    business_impact: String,
    fix_suggestion: String,
    similar_exploits: Vec<ExploitReference>,
}

#[derive(Deserialize)]
struct BatchExplanationResponse {
    explanations: Vec<AIExplanationResponse>,
}

const SYSTEM_PROMPT: &str = r#"
You are an elite smart contract security expert with deep knowledge of:
- All historical DeFi exploits (Terra/Luna, Wormhole, Nomad, Euler, etc.)
- Cross-contract interaction vulnerabilities
- Economic game theory in blockchain systems
- EVM bytecode analysis

Your explanations should be:
1. ACCURATE: Technically correct and precise
2. ACCESSIBLE: Understandable by smart developers (not just security experts)
3. ACTIONABLE: Include specific code fixes and recommendations
4. REFERENCED: Cite real exploits when relevant with dates and amounts
5. BUSINESS-FOCUSED: Explain $ impact and reputation risk

Remember: The vulnerability detection is PROVEN (cryptographically verified).
Your job is only to EXPLAIN clearly, not to question whether it exists.
"#;
