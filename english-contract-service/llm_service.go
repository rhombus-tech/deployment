package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// LLMService handles translation using language models
type LLMService interface {
	TranslateToRust(ctx context.Context, contract *EnglishContract) (string, error)
	IsHealthy() bool
}

type anthropicLLMService struct {
	apiKey     string
	model      string
	httpClient *http.Client
}

func NewLLMService() LLMService {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY") // Fallback to OpenAI
	}
	
	return &anthropicLLMService{
		apiKey: apiKey,
		model:  DefaultLLMModel,
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (s *anthropicLLMService) TranslateToRust(ctx context.Context, contract *EnglishContract) (string, error) {
	// Build the prompt with contract details
	prompt := s.buildTranslationPrompt(contract)
	
	// Call Claude API
	rustCode, err := s.callClaude(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("LLM translation failed: %w", err)
	}
	
	// Extract code from markdown if needed
	rustCode = extractRustCode(rustCode)
	
	// Validate generated Rust code
	if err := validateRustSyntax(rustCode); err != nil {
		return "", fmt.Errorf("generated invalid Rust: %w", err)
	}
	
	return rustCode, nil
}

func (s *anthropicLLMService) buildTranslationPrompt(contract *EnglishContract) string {
	var prompt strings.Builder
	
	prompt.WriteString("You are an expert Rust developer specializing in WebAssembly smart contracts. ")
	prompt.WriteString("Translate the following English contract specification into production-ready Rust code ")
	prompt.WriteString("that compiles to WASM for blockchain execution.\n\n")
	
	prompt.WriteString("CRITICAL REQUIREMENTS:\n")
	prompt.WriteString("1. Use #[no_mangle] and extern \"C\" for all exported functions\n")
	prompt.WriteString("2. Implement proper bounds checking (max parameter size: 1024 bytes)\n")
	prompt.WriteString("3. Handle errors gracefully - return empty vectors instead of panicking\n")
	prompt.WriteString("4. Use Borsh serialization for state management\n")
	prompt.WriteString("5. Implement all security checks specified in requirements\n")
	prompt.WriteString("6. Add comprehensive error handling for all operations\n")
	prompt.WriteString("7. Ensure deterministic execution (no random, no system calls)\n")
	prompt.WriteString("8. Optimize for WASM size and gas efficiency\n\n")
	
	prompt.WriteString("CONTRACT SPECIFICATION:\n")
	prompt.WriteString("======================\n\n")
	
	// Contract header
	prompt.WriteString(fmt.Sprintf("NAME: %s\n", contract.Name))
	prompt.WriteString(fmt.Sprintf("DESCRIPTION: %s\n\n", contract.Description))
	
	// Configuration
	if len(contract.Config) > 0 {
		prompt.WriteString("CONFIGURATION:\n")
		for key, value := range contract.Config {
			prompt.WriteString(fmt.Sprintf("- %s: %s\n", key, value))
		}
		prompt.WriteString("\n")
	}
	
	// State variables
	if len(contract.State) > 0 {
		prompt.WriteString("STATE VARIABLES:\n")
		for _, state := range contract.State {
			prompt.WriteString(fmt.Sprintf("- %s: %s (%s)\n", state.Name, state.Type, state.Description))
		}
		prompt.WriteString("\n")
	}
	
	// Functions
	prompt.WriteString("FUNCTIONS:\n")
	for i, fn := range contract.Functions {
		prompt.WriteString(fmt.Sprintf("\n%d. FUNCTION: %s\n", i+1, fn.Name))
		if fn.Description != "" {
			prompt.WriteString(fmt.Sprintf("   Description: %s\n", fn.Description))
		}
		
		if len(fn.Parameters) > 0 {
			prompt.WriteString("   Parameters:\n")
			for _, param := range fn.Parameters {
				prompt.WriteString(fmt.Sprintf("   - %s: %s (%s)\n", param.Name, param.Type, param.Description))
			}
		}
		
		if len(fn.Returns) > 0 {
			prompt.WriteString("   Returns:\n")
			for _, ret := range fn.Returns {
				prompt.WriteString(fmt.Sprintf("   - %s: %s\n", ret.Type, ret.Description))
			}
		}
		
		if len(fn.Requirements) > 0 {
			prompt.WriteString("   Requirements:\n")
			for _, req := range fn.Requirements {
				prompt.WriteString(fmt.Sprintf("   - %s\n", req))
			}
		}
		
		if len(fn.Steps) > 0 {
			prompt.WriteString("   Implementation:\n")
			for _, step := range fn.Steps {
				prompt.WriteString(fmt.Sprintf("   - %s\n", step))
			}
		}
	}
	
	// Events
	if len(contract.Events) > 0 {
		prompt.WriteString("\nEVENTS:\n")
		for _, event := range contract.Events {
			prompt.WriteString(fmt.Sprintf("- %s", event.Name))
			if len(event.Parameters) > 0 {
				paramNames := []string{}
				for _, param := range event.Parameters {
					paramNames = append(paramNames, fmt.Sprintf("%s: %s", param.Name, param.Type))
				}
				prompt.WriteString(fmt.Sprintf("(%s)", strings.Join(paramNames, ", ")))
			}
			prompt.WriteString("\n")
		}
	}
	
	prompt.WriteString("\n======================\n\n")
	
	prompt.WriteString("Generate complete, production-ready Rust code that:\n")
	prompt.WriteString("- Compiles to WASM without errors\n")
	prompt.WriteString("- Implements all functions exactly as specified\n")
	prompt.WriteString("- Includes all security checks from requirements\n")
	prompt.WriteString("- Has proper error handling and validation\n")
	prompt.WriteString("- Uses safe parameter handling (validate length prefix)\n")
	prompt.WriteString("- Returns only the Rust code, no explanation\n")
	
	return prompt.String()
}

func (s *anthropicLLMService) callClaude(ctx context.Context, prompt string) (string, error) {
	url := "https://api.anthropic.com/v1/messages"
	
	requestBody := map[string]interface{}{
		"model": s.model,
		"max_tokens": MaxTokens,
		"temperature": Temperature,
		"messages": []map[string]string{
			{
				"role": "user",
				"content": prompt,
			},
		},
	}
	
	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", s.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}
	
	var response struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}
	
	if len(response.Content) == 0 {
		return "", fmt.Errorf("empty response from API")
	}
	
	return response.Content[0].Text, nil
}

func (s *anthropicLLMService) IsHealthy() bool {
	return s.apiKey != ""
}

// extractRustCode extracts Rust code from markdown code blocks
func extractRustCode(text string) string {
	// Look for ```rust code blocks
	start := strings.Index(text, "```rust")
	if start == -1 {
		start = strings.Index(text, "```")
	}
	
	if start != -1 {
		// Find end of code block
		end := strings.Index(text[start+7:], "```")
		if end != -1 {
			return strings.TrimSpace(text[start+7 : start+7+end])
		}
	}
	
	// No code block found, return as-is
	return strings.TrimSpace(text)
}

// validateRustSyntax performs basic validation of Rust syntax
func validateRustSyntax(code string) error {
	// Check for required exports
	if !strings.Contains(code, "#[no_mangle]") {
		return fmt.Errorf("missing #[no_mangle] attribute")
	}
	
	if !strings.Contains(code, "extern \"C\"") {
		return fmt.Errorf("missing extern \"C\" declaration")
	}
	
	// Check for dangerous patterns
	dangerousPatterns := []string{
		"unsafe {",
		"std::process",
		"std::fs",
		"std::net",
		"std::io::stdin",
	}
	
	for _, pattern := range dangerousPatterns {
		if strings.Contains(code, pattern) {
			return fmt.Errorf("contains dangerous pattern: %s", pattern)
		}
	}
	
	// Basic brace matching
	openBraces := strings.Count(code, "{")
	closeBraces := strings.Count(code, "}")
	
	if openBraces != closeBraces {
		return fmt.Errorf("mismatched braces: %d open, %d close", openBraces, closeBraces)
	}
	
	return nil
}
