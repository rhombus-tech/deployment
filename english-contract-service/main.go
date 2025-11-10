package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

const (
	// API Configuration
	DefaultPort = "8080"
	APIVersion  = "v1"
	
	// LLM Configuration
	DefaultLLMModel = "claude-3-5-sonnet-20241022"
	MaxTokens       = 8000
	Temperature     = 0.2 // Low temperature for deterministic code generation
)

// Server represents the English contract translation server
type Server struct {
	router       *http.Router
	teeClient    TEEClient
	llmService   LLMService
	verifier     WasmVerifier
	compiler     RustCompiler
	templateRepo TemplateRepository
}

// EnglishContract represents a contract written in natural language
type EnglishContract struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Config      map[string]string   `json:"config"`
	State       []StateVariable     `json:"state"`
	Functions   []ContractFunction  `json:"functions"`
	Events      []ContractEvent     `json:"events"`
	RawText     string              `json:"raw_text"`
}

// StateVariable represents a contract state variable
type StateVariable struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Initial     string `json:"initial_value,omitempty"`
}

// ContractFunction represents a function in the contract
type ContractFunction struct {
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	Parameters   []Parameter  `json:"parameters"`
	Returns      []ReturnType `json:"returns"`
	Requirements []string     `json:"requirements"`
	Steps        []string     `json:"steps"`
	Visibility   string       `json:"visibility"` // "public", "private", "internal"
}

// Parameter represents a function parameter
type Parameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

// ReturnType represents a function return value
type ReturnType struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// ContractEvent represents an event that can be emitted
type ContractEvent struct {
	Name       string      `json:"name"`
	Parameters []Parameter `json:"parameters"`
}

// TranslationRequest represents a request to translate English to WASM
type TranslationRequest struct {
	EnglishContract EnglishContract `json:"english_contract"`
	TargetLanguage  string          `json:"target_language"` // "rust", "go", etc.
	Optimization    string          `json:"optimization"`    // "safety", "performance", "size"
	TEEExecution    bool            `json:"tee_execution"`   // Execute LLM in TEE
}

// TranslationResponse represents the response with generated code
type TranslationResponse struct {
	Success          bool              `json:"success"`
	RustCode         string            `json:"rust_code,omitempty"`
	WasmBytecode     []byte            `json:"wasm_bytecode,omitempty"`
	VerificationProof *VerificationProof `json:"verification_proof,omitempty"`
	Errors           []string          `json:"errors,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	Metadata         TranslationMetadata `json:"metadata"`
}

// TranslationMetadata contains metadata about the translation
type TranslationMetadata struct {
	TranslationTime  time.Duration `json:"translation_time_ms"`
	CompilationTime  time.Duration `json:"compilation_time_ms"`
	VerificationTime time.Duration `json:"verification_time_ms"`
	WasmSize         int           `json:"wasm_size_bytes"`
	SafetyScore      float64       `json:"safety_score"` // 0-100
	ComplexityScore  int           `json:"complexity_score"`
	GasEstimate      uint64        `json:"gas_estimate"`
}

// VerificationProof represents the verification results
type VerificationProof struct {
	MemorySafe      bool     `json:"memory_safe"`
	TypeSafe        bool     `json:"type_safe"`
	BoundsChecked   bool     `json:"bounds_checked"`
	NoLeaks         bool     `json:"no_leaks"`
	Deterministic   bool     `json:"deterministic"`
	SideChannelSafe bool     `json:"side_channel_safe"`
	Violations      []string `json:"violations,omitempty"`
	ProofHash       string   `json:"proof_hash"`
}

func main() {
	// Initialize server
	server := NewServer()
	
	// Setup routes
	router := mux.NewRouter()
	
	// API routes
	api := router.PathPrefix("/api/" + APIVersion).Subrouter()
	
	// Translation endpoints
	api.HandleFunc("/translate", server.HandleTranslate).Methods("POST")
	api.HandleFunc("/translate/stream", server.HandleTranslateStream).Methods("POST")
	api.HandleFunc("/validate", server.HandleValidate).Methods("POST")
	
	// Template endpoints
	api.HandleFunc("/templates", server.HandleListTemplates).Methods("GET")
	api.HandleFunc("/templates/{name}", server.HandleGetTemplate).Methods("GET")
	
	// Contract examples
	api.HandleFunc("/examples", server.HandleListExamples).Methods("GET")
	api.HandleFunc("/examples/{name}", server.HandleGetExample).Methods("GET")
	
	// Verification endpoints
	api.HandleFunc("/verify", server.HandleVerify).Methods("POST")
	api.HandleFunc("/verify/proof/{hash}", server.HandleGetProof).Methods("GET")
	
	// Health and status
	api.HandleFunc("/health", server.HandleHealth).Methods("GET")
	api.HandleFunc("/status", server.HandleStatus).Methods("GET")
	
	// Serve static files (Web UI)
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./web")))
	
	// CORS configuration
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})
	
	handler := c.Handler(router)
	
	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}
	
	log.Printf("🚀 English Contract Service starting on port %s", port)
	log.Printf("📝 API Documentation: http://localhost:%s/api/%s/docs", port, APIVersion)
	log.Printf("🌐 Web UI: http://localhost:%s", port)
	
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

func NewServer() *Server {
	return &Server{
		teeClient:    NewTEEClient(),
		llmService:   NewLLMService(),
		verifier:     NewWasmVerifier(),
		compiler:     NewRustCompiler(),
		templateRepo: NewTemplateRepository(),
	}
}

// HandleTranslate handles the main translation endpoint
func (s *Server) HandleTranslate(w http.ResponseWriter, r *http.Request) {
	var req TranslationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	startTime := time.Now()
	
	// Step 1: Validate English contract
	if err := s.validateEnglishContract(&req.EnglishContract); err != nil {
		response := TranslationResponse{
			Success: false,
			Errors:  []string{fmt.Sprintf("Validation error: %v", err)},
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	// Step 2: Translate English to Rust (in TEE if requested)
	var rustCode string
	var err error
	
	if req.TEEExecution {
		// Execute LLM translation inside TEE for maximum security
		rustCode, err = s.translateInTEE(r.Context(), &req.EnglishContract)
	} else {
		// Standard translation
		rustCode, err = s.llmService.TranslateToRust(r.Context(), &req.EnglishContract)
	}
	
	translationTime := time.Since(startTime)
	
	if err != nil {
		response := TranslationResponse{
			Success: false,
			Errors:  []string{fmt.Sprintf("Translation error: %v", err)},
			Metadata: TranslationMetadata{
				TranslationTime: translationTime,
			},
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	// Step 3: Compile Rust to WASM
	compileStart := time.Now()
	wasmBytes, compileErr := s.compiler.CompileToWasm(rustCode)
	compilationTime := time.Since(compileStart)
	
	if compileErr != nil {
		response := TranslationResponse{
			Success:  false,
			RustCode: rustCode,
			Errors:   []string{fmt.Sprintf("Compilation error: %v", compileErr)},
			Metadata: TranslationMetadata{
				TranslationTime:  translationTime,
				CompilationTime:  compilationTime,
			},
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	// Step 4: Verify WASM with your existing verification system
	verifyStart := time.Now()
	proof, verifyErr := s.verifier.Verify(wasmBytes)
	verificationTime := time.Since(verifyStart)
	
	if verifyErr != nil {
		response := TranslationResponse{
			Success:      false,
			RustCode:     rustCode,
			WasmBytecode: wasmBytes,
			Errors:       []string{fmt.Sprintf("Verification failed: %v", verifyErr)},
			Metadata: TranslationMetadata{
				TranslationTime:  translationTime,
				CompilationTime:  compilationTime,
				VerificationTime: verificationTime,
				WasmSize:         len(wasmBytes),
			},
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	// Success! Return everything
	response := TranslationResponse{
		Success:           true,
		RustCode:          rustCode,
		WasmBytecode:      wasmBytes,
		VerificationProof: proof,
		Metadata: TranslationMetadata{
			TranslationTime:  translationTime,
			CompilationTime:  compilationTime,
			VerificationTime: verificationTime,
			WasmSize:         len(wasmBytes),
			SafetyScore:      calculateSafetyScore(proof),
			ComplexityScore:  calculateComplexity(&req.EnglishContract),
			GasEstimate:      estimateGas(wasmBytes),
		},
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleTranslateStream handles streaming translation (real-time updates)
func (s *Server) HandleTranslateStream(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	
	var req TranslationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	// Send progress updates
	sendEvent := func(event string, data interface{}) {
		jsonData, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, jsonData)
		w.(http.Flusher).Flush()
	}
	
	sendEvent("status", map[string]string{"stage": "validating", "message": "Validating English contract..."})
	
	if err := s.validateEnglishContract(&req.EnglishContract); err != nil {
		sendEvent("error", map[string]string{"error": err.Error()})
		return
	}
	
	sendEvent("status", map[string]string{"stage": "translating", "message": "Translating to Rust..."})
	
	rustCode, err := s.llmService.TranslateToRust(r.Context(), &req.EnglishContract)
	if err != nil {
		sendEvent("error", map[string]string{"error": err.Error()})
		return
	}
	
	sendEvent("rust_code", map[string]string{"code": rustCode})
	sendEvent("status", map[string]string{"stage": "compiling", "message": "Compiling to WASM..."})
	
	wasmBytes, err := s.compiler.CompileToWasm(rustCode)
	if err != nil {
		sendEvent("error", map[string]string{"error": err.Error()})
		return
	}
	
	sendEvent("status", map[string]string{"stage": "verifying", "message": "Running safety verification..."})
	
	proof, err := s.verifier.Verify(wasmBytes)
	if err != nil {
		sendEvent("error", map[string]string{"error": err.Error()})
		return
	}
	
	sendEvent("complete", map[string]interface{}{
		"wasm_size": len(wasmBytes),
		"proof":     proof,
	})
}

// HandleValidate validates an English contract without translating
func (s *Server) HandleValidate(w http.ResponseWriter, r *http.Request) {
	var contract EnglishContract
	if err := json.NewDecoder(r.Body).Decode(&contract); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	errors := []string{}
	warnings := []string{}
	
	// Validate contract structure
	if contract.Name == "" {
		errors = append(errors, "Contract name is required")
	}
	
	if len(contract.Functions) == 0 {
		warnings = append(warnings, "Contract has no functions")
	}
	
	// Check for common issues
	for _, fn := range contract.Functions {
		if fn.Name == "" {
			errors = append(errors, "Function missing name")
		}
		
		if len(fn.Requirements) == 0 {
			warnings = append(warnings, fmt.Sprintf("Function '%s' has no requirements (potential security risk)", fn.Name))
		}
		
		// Check for dangerous patterns
		for _, step := range fn.Steps {
			if strings.Contains(strings.ToLower(step), "transfer all") {
				warnings = append(warnings, fmt.Sprintf("Function '%s' contains 'transfer all' - potential drain vulnerability", fn.Name))
			}
		}
	}
	
	response := map[string]interface{}{
		"valid":    len(errors) == 0,
		"errors":   errors,
		"warnings": warnings,
	}
	
	json.NewEncoder(w).Encode(response)
}

// HandleListTemplates returns available contract templates
func (s *Server) HandleListTemplates(w http.ResponseWriter, r *http.Request) {
	templates := s.templateRepo.List()
	json.NewEncoder(w).Encode(templates)
}

// HandleGetTemplate returns a specific template
func (s *Server) HandleGetTemplate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	
	template, err := s.templateRepo.Get(name)
	if err != nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}
	
	json.NewEncoder(w).Encode(template)
}

// HandleListExamples returns example contracts
func (s *Server) HandleListExamples(w http.ResponseWriter, r *http.Request) {
	examples := []map[string]string{
		{"name": "simple_token", "description": "Basic ERC20-like token"},
		{"name": "escrow", "description": "Simple escrow with arbitration"},
		{"name": "amm", "description": "Automated market maker (DEX)"},
		{"name": "dao", "description": "Decentralized autonomous organization"},
		{"name": "nft", "description": "Non-fungible token contract"},
		{"name": "staking", "description": "Token staking with rewards"},
	}
	
	json.NewEncoder(w).Encode(examples)
}

// HandleGetExample returns a specific example
func (s *Server) HandleGetExample(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	
	// Load example from file or database
	example, err := loadExample(name)
	if err != nil {
		http.Error(w, "Example not found", http.StatusNotFound)
		return
	}
	
	json.NewEncoder(w).Encode(example)
}

// HandleVerify verifies WASM bytecode
func (s *Server) HandleVerify(w http.ResponseWriter, r *http.Request) {
	// Read WASM bytes from request
	wasmBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	proof, err := s.verifier.Verify(wasmBytes)
	if err != nil {
		response := map[string]interface{}{
			"verified": false,
			"error":    err.Error(),
		}
		json.NewEncoder(w).Encode(response)
		return
	}
	
	response := map[string]interface{}{
		"verified": true,
		"proof":    proof,
	}
	
	json.NewEncoder(w).Encode(response)
}

// HandleGetProof retrieves a verification proof by hash
func (s *Server) HandleGetProof(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hash := vars["hash"]
	
	// Retrieve proof from storage
	proof, err := s.verifier.GetProof(hash)
	if err != nil {
		http.Error(w, "Proof not found", http.StatusNotFound)
		return
	}
	
	json.NewEncoder(w).Encode(proof)
}

// HandleHealth returns service health status
func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"services": map[string]bool{
			"tee":      s.teeClient.IsHealthy(),
			"llm":      s.llmService.IsHealthy(),
			"verifier": s.verifier.IsHealthy(),
			"compiler": s.compiler.IsHealthy(),
		},
	}
	
	json.NewEncoder(w).Encode(health)
}

// HandleStatus returns detailed service status
func (s *Server) HandleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"version":    APIVersion,
		"uptime":     time.Since(startTime).Seconds(),
		"requests":   requestCounter.Load(),
		"errors":     errorCounter.Load(),
		"tee_enabled": s.teeClient != nil,
	}
	
	json.NewEncoder(w).Encode(status)
}

// Helper functions

func (s *Server) validateEnglishContract(contract *EnglishContract) error {
	if contract.Name == "" {
		return fmt.Errorf("contract name is required")
	}
	
	if len(contract.Functions) == 0 {
		return fmt.Errorf("contract must have at least one function")
	}
	
	return nil
}

func (s *Server) translateInTEE(ctx context.Context, contract *EnglishContract) (string, error) {
	// Execute LLM translation inside TEE for maximum security
	request := map[string]interface{}{
		"contract": contract,
		"model":    DefaultLLMModel,
	}
	
	requestBytes, _ := json.Marshal(request)
	
	result, err := s.teeClient.Execute(ctx, "llm-translate", requestBytes)
	if err != nil {
		return "", err
	}
	
	return string(result), nil
}

func calculateSafetyScore(proof *VerificationProof) float64 {
	score := 0.0
	checks := 6.0
	
	if proof.MemorySafe {
		score += 100.0 / checks
	}
	if proof.TypeSafe {
		score += 100.0 / checks
	}
	if proof.BoundsChecked {
		score += 100.0 / checks
	}
	if proof.NoLeaks {
		score += 100.0 / checks
	}
	if proof.Deterministic {
		score += 100.0 / checks
	}
	if proof.SideChannelSafe {
		score += 100.0 / checks
	}
	
	return score
}

func calculateComplexity(contract *EnglishContract) int {
	complexity := 0
	
	// Cyclomatic complexity estimation
	for _, fn := range contract.Functions {
		complexity += 1 // Base complexity
		complexity += len(fn.Requirements)
		
		// Count conditional logic in steps
		for _, step := range fn.Steps {
			if strings.Contains(strings.ToLower(step), "if ") {
				complexity += 1
			}
			if strings.Contains(strings.ToLower(step), "for ") {
				complexity += 2
			}
			if strings.Contains(strings.ToLower(step), "while ") {
				complexity += 2
			}
		}
	}
	
	return complexity
}

func estimateGas(wasmBytes []byte) uint64 {
	// Simple gas estimation based on WASM size
	// In production, run static analysis
	baseGas := uint64(21000)
	sizeGas := uint64(len(wasmBytes)) * 100
	
	return baseGas + sizeGas
}

func loadExample(name string) (*EnglishContract, error) {
	// Load from examples directory or database
	// This is a placeholder
	return nil, fmt.Errorf("not implemented")
}

var (
	startTime      = time.Now()
	requestCounter atomic.Uint64
	errorCounter   atomic.Uint64
)
