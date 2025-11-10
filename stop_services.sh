#!/bin/bash
# Stop TEE Mesh Blockchain Services

set -e

DATA_DIR="/var/lib/tee_mesh_blockchain"
LOG_DIR="/var/log/tee_mesh_blockchain"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

stop_service() {
    local service_name="$1"
    local pid_file="$2"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p "$pid" > /dev/null 2>&1; then
            log_info "Stopping $service_name (PID: $pid)..."
            kill $pid
            sleep 2
            
            # Force kill if still running
            if ps -p "$pid" > /dev/null 2>&1; then
                log_info "Force stopping $service_name..."
                kill -9 $pid
            fi
            
            log_success "$service_name stopped"
        else
            log_info "$service_name was not running"
        fi
        rm -f "$pid_file"
    else
        log_info "$service_name PID file not found"
    fi
}

echo "🛑 Stopping TEE Mesh Blockchain Services"
echo "========================================"

stop_service "HyperTeeController" "$DATA_DIR/tee_controller.pid"
stop_service "zkEVM Server" "$DATA_DIR/zkevm_server.pid"
stop_service "StatelessVM" "$DATA_DIR/stateless_vm.pid"
stop_service "Ethereum Bridge" "$DATA_DIR/ethereum_bridge.pid"
stop_service "Avalanche Bridge" "$DATA_DIR/avalanche_bridge.pid"

log_success "All services stopped"
echo "📁 Logs preserved in: $LOG_DIR"
