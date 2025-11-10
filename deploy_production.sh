#!/bin/bash
# Production Deployment Script for TEE Mesh Blockchain
# Deploys real integration with Aristo TEE mesh, bridges, and scaling

set -e

echo "🚀 TEE Mesh Blockchain Production Deployment"
echo "=============================================="

# Configuration
DEPLOYMENT_DIR="/Users/talzisckind/Downloads/deployment"
ARISTO_DIR="/Users/talzisckind/Downloads/aristo-fresh 2"
CONFIG_FILE="$DEPLOYMENT_DIR/production_config.toml"
LOG_DIR="/var/log/tee_mesh_blockchain"
DATA_DIR="/var/lib/tee_mesh_blockchain"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Step 1: Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if Rust is installed
    if ! command -v rustc &> /dev/null; then
        log_error "Rust is not installed. Please install Rust first."
        exit 1
    fi
    
    # Check if cargo is installed
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo is not installed. Please install Cargo first."
        exit 1
    fi
    
    # Check if configuration file exists
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Production configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Check if Aristo directory exists
    if [ ! -d "$ARISTO_DIR" ]; then
        log_error "Aristo TEE mesh directory not found: $ARISTO_DIR"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Step 2: Create necessary directories
setup_directories() {
    log_info "Setting up directories..."
    
    # Create log directory
    sudo mkdir -p "$LOG_DIR"
    sudo chown $USER:$USER "$LOG_DIR"
    
    # Create data directory
    sudo mkdir -p "$DATA_DIR"
    sudo chown $USER:$USER "$DATA_DIR"
    
    # Create subdirectories
    mkdir -p "$DATA_DIR/state"
    mkdir -p "$DATA_DIR/backups"
    mkdir -p "$DATA_DIR/cache"
    
    log_success "Directories created"
}

# Step 3: Build Aristo TEE mesh components
build_aristo_components() {
    log_info "Building Aristo TEE mesh components..."
    
    cd "$ARISTO_DIR/execution/controller"
    log_info "Building HyperTeeController..."
    cargo build --release
    
    if [ ! -f "target/release/aristo_client" ]; then
        log_warning "Release build failed, trying debug build..."
        cargo build
        if [ ! -f "target/debug/aristo_client" ]; then
            log_error "Failed to build HyperTeeController"
            exit 1
        fi
    fi
    
    log_success "Aristo TEE mesh components built"
}

# Step 4: Build zkEVM components
build_zkevm_components() {
    log_info "Building zkEVM components..."
    
    cd "$DEPLOYMENT_DIR/evm-verify"
    log_info "Building zkEVM proof generation server..."
    cargo build --release --features "pcd,accumulation"
    
    if [ ! -f "target/release/simple-production-server" ]; then
        log_warning "Release build failed, trying debug build..."
        cargo build --features "pcd,accumulation"
        if [ ! -f "target/debug/simple-production-server" ]; then
            log_error "Failed to build zkEVM server"
            exit 1
        fi
    fi
    
    log_success "zkEVM components built"
}

# Step 5: Build StatelessVM
build_stateless_vm() {
    log_info "Building StatelessVM..."
    
    cd "$DEPLOYMENT_DIR/stateless-vm"
    log_info "Building StatelessVM verifier..."
    cargo build --release
    
    if [ ! -f "target/release/stateless_vm" ]; then
        log_warning "Release build failed, trying debug build..."
        cargo build
        if [ ! -f "target/debug/stateless_vm" ]; then
            log_error "Failed to build StatelessVM"
            exit 1
        fi
    fi
    
    log_success "StatelessVM built"
}

# Step 6: Build bridge services
build_bridge_services() {
    log_info "Building bridge services..."
    
    # Build Ethereum bridge service (Go)
    cd "$ARISTO_DIR/ethereum_integration"
    log_info "Building Ethereum settlement bridge..."
    go build -o ethereum_bridge_service ./mesh_ethereum_bridge.go
    
    # Build Avalanche bridge service (Go)
    cd "$ARISTO_DIR/tee/rlnc"
    log_info "Building Avalanche mesh bridge..."
    go build -o avalanche_bridge_service ./avalanche_integration.go
    
    log_success "Bridge services built"
}

# Step 7: Deploy smart contracts (if needed)
deploy_smart_contracts() {
    log_info "Checking smart contract deployment..."
    
    # Check if Ethereum contract is deployed
    CONTRACT_ADDRESS=$(grep "contract_address" "$CONFIG_FILE" | cut -d'"' -f4)
    if [ "$CONTRACT_ADDRESS" = "0x1234567890123456789012345678901234567890" ]; then
        log_warning "Default contract address detected. Deploy UltimateHybridSettlement.sol to Ethereum mainnet"
        log_warning "Update contract_address in $CONFIG_FILE with actual deployed address"
    fi
    
    log_success "Smart contract check completed"
}

# Step 8: Start services
start_services() {
    log_info "Starting TEE Mesh Blockchain services..."
    
    # Start HyperTeeController
    log_info "Starting HyperTeeController..."
    cd "$ARISTO_DIR/execution/controller"
    nohup ./target/debug/aristo_client --config "$CONFIG_FILE" > "$LOG_DIR/tee_controller.log" 2>&1 &
    TEE_CONTROLLER_PID=$!
    echo $TEE_CONTROLLER_PID > "$DATA_DIR/tee_controller.pid"
    
    # Wait for TEE controller to start
    sleep 5
    
    # Start zkEVM proof generation server
    log_info "Starting zkEVM server..."
    cd "$DEPLOYMENT_DIR/evm-verify"
    nohup ./target/debug/simple-production-server --config "$DEPLOYMENT_DIR/config/config/zkvm-prod.toml" > "$LOG_DIR/zkevm_server.log" 2>&1 &
    ZKEVM_PID=$!
    echo $ZKEVM_PID > "$DATA_DIR/zkevm_server.pid"
    
    # Start StatelessVM
    log_info "Starting StatelessVM..."
    cd "$DEPLOYMENT_DIR/stateless-vm"
    nohup ./target/debug/stateless_vm --config "$DEPLOYMENT_DIR/stateless-vm/config.toml" > "$LOG_DIR/stateless_vm.log" 2>&1 &
    STATELESS_VM_PID=$!
    echo $STATELESS_VM_PID > "$DATA_DIR/stateless_vm.pid"
    
    # Start Ethereum bridge service
    log_info "Starting Ethereum bridge..."
    cd "$ARISTO_DIR/ethereum_integration"
    nohup ./ethereum_bridge_service --config "$CONFIG_FILE" --port 9090 > "$LOG_DIR/ethereum_bridge.log" 2>&1 &
    ETH_BRIDGE_PID=$!
    echo $ETH_BRIDGE_PID > "$DATA_DIR/ethereum_bridge.pid"
    
    # Start Avalanche bridge service
    log_info "Starting Avalanche bridge..."
    cd "$ARISTO_DIR/tee/rlnc"
    nohup ./avalanche_bridge_service --config "$CONFIG_FILE" --port 9091 > "$LOG_DIR/avalanche_bridge.log" 2>&1 &
    AVAX_BRIDGE_PID=$!
    echo $AVAX_BRIDGE_PID > "$DATA_DIR/avalanche_bridge.pid"
    
    # Wait for all services to start
    sleep 10
    
    log_success "All services started"
}

# Step 9: Health checks
run_health_checks() {
    log_info "Running health checks..."
    
    # Check if services are running
    check_service() {
        local service_name="$1"
        local pid_file="$2"
        local port="$3"
        
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file")
            if ps -p "$pid" > /dev/null 2>&1; then
                log_success "$service_name is running (PID: $pid)"
                
                # Check if service responds on port
                if [ -n "$port" ]; then
                    if curl -f "http://localhost:$port/health" &> /dev/null; then
                        log_success "$service_name health check passed"
                    else
                        log_warning "$service_name is running but health check failed"
                    fi
                fi
            else
                log_error "$service_name is not running (PID file exists but process not found)"
            fi
        else
            log_error "$service_name PID file not found"
        fi
    }
    
    check_service "HyperTeeController" "$DATA_DIR/tee_controller.pid" "8080"
    check_service "zkEVM Server" "$DATA_DIR/zkevm_server.pid" "8082"
    check_service "StatelessVM" "$DATA_DIR/stateless_vm.pid" "8083"
    check_service "Ethereum Bridge" "$DATA_DIR/ethereum_bridge.pid" "9090"
    check_service "Avalanche Bridge" "$DATA_DIR/avalanche_bridge.pid" "9091"
}

# Step 10: Run integration test
run_integration_test() {
    log_info "Running integration test with real components..."
    
    cd "$DEPLOYMENT_DIR"
    
    # Compile and run the working integration test
    rustc --edition 2021 working_integration_test.rs -o production_integration_test
    
    log_info "Executing production integration test..."
    ./production_integration_test
    
    if [ $? -eq 0 ]; then
        log_success "Integration test passed - TEE Mesh Blockchain is operational!"
    else
        log_error "Integration test failed"
        exit 1
    fi
}

# Step 11: Display status and next steps
display_status() {
    echo ""
    log_success "🎉 TEE Mesh Blockchain Production Deployment Complete!"
    echo ""
    echo "📊 Service Status:"
    echo "   • HyperTeeController: http://localhost:8080"
    echo "   • zkEVM Server: http://localhost:8082"
    echo "   • StatelessVM: http://localhost:8083"
    echo "   • Ethereum Bridge: http://localhost:9090"
    echo "   • Avalanche Bridge: http://localhost:9091"
    echo ""
    echo "📁 Important Files:"
    echo "   • Config: $CONFIG_FILE"
    echo "   • Logs: $LOG_DIR/"
    echo "   • Data: $DATA_DIR/"
    echo ""
    echo "🔧 Management Commands:"
    echo "   • Stop services: ./stop_services.sh"
    echo "   • View logs: tail -f $LOG_DIR/*.log"
    echo "   • Health check: ./health_check.sh"
    echo ""
    echo "🚀 Next Steps:"
    echo "   1. Update Ethereum contract address in config if not deployed"
    echo "   2. Configure monitoring and alerting"
    echo "   3. Set up backup and disaster recovery"
    echo "   4. Configure load balancing for scaling"
    echo "   5. Deploy to production environment"
    echo ""
    log_info "TEE Mesh Blockchain is ready for production use!"
}

# Main deployment flow
main() {
    check_prerequisites
    setup_directories
    build_aristo_components
    build_zkevm_components
    build_stateless_vm
    build_bridge_services
    deploy_smart_contracts
    start_services
    run_health_checks
    run_integration_test
    display_status
}

# Run deployment
main "$@"
