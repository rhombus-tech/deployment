.PHONY: help build test deploy clean docker k8s

help:
	@echo "🚀 Trustless Proving Network - Production Makefile"
	@echo ""
	@echo "Commands:"
	@echo "  make build          - Build all components"
	@echo "  make test           - Run all tests"
	@echo "  make test-load      - Run load tests"
	@echo "  make docker         - Build Docker images"
	@echo "  make deploy-staging - Deploy to staging"
	@echo "  make deploy-prod    - Deploy to production"
	@echo "  make clean          - Clean build artifacts"
	@echo ""

build:
	@echo "🔨 Building Rust components..."
	cargo build --release --bin trustless-proving-server
	@echo "🔨 Building smart contracts..."
	npx hardhat compile
	@echo "🔨 Building TypeScript SDK..."
	cd trustless-sdk && npm run build
	@echo "✅ Build complete"

test:
	@echo "🧪 Running tests..."
	chmod +x test-production.sh
	./test-production.sh

test-load:
	@echo "⚡ Running load tests..."
	@echo "Starting server..."
	@ENABLE_FRACTAL=true ./target/release/trustless-proving-server > /tmp/server.log 2>&1 & echo $$! > /tmp/server.pid
	@sleep 3
	@node load-test.js
	@kill `cat /tmp/server.pid` 2>/dev/null || true

docker:
	@echo "🐳 Building Docker image..."
	docker build -f Dockerfile.proving-server -t trustless/proving-server:latest .
	docker build -f Dockerfile.proving-server -t trustless/proving-server:$(shell git rev-parse --short HEAD) .
	@echo "✅ Docker images built"

docker-push:
	@echo "📤 Pushing Docker images..."
	docker push trustless/proving-server:latest
	docker push trustless/proving-server:$(shell git rev-parse --short HEAD)

deploy-local:
	@echo "🏠 Deploying locally with docker-compose..."
	docker-compose up -d
	@echo "✅ Local deployment complete"
	@echo "   API: http://localhost:3000"
	@echo "   Grafana: http://localhost:3001"

deploy-staging:
	@echo "🚀 Deploying to staging..."
	@DEPLOY_ENV=staging ./deploy.sh

deploy-prod:
	@echo "🚀 Deploying to production..."
	@read -p "Are you sure you want to deploy to PRODUCTION? (yes/no): " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		DEPLOY_ENV=production ./deploy.sh; \
	else \
		echo "❌ Deployment cancelled"; \
	fi

clean:
	@echo "🧹 Cleaning..."
	cargo clean
	rm -rf target/
	rm -rf trustless-sdk/dist/
	rm -rf node_modules/.cache/
	docker-compose down -v 2>/dev/null || true
	@echo "✅ Clean complete"

contracts-deploy:
	@echo "📜 Deploying smart contracts..."
	npx hardhat run scripts/deploy-contracts.ts --network mainnet

contracts-verify:
	@echo "🔍 Verifying contracts on Etherscan..."
	@echo "Run: npx hardhat verify --network mainnet <CONTRACT_ADDRESS>"

all: build test docker

.DEFAULT_GOAL := help
