// AI Agent Security Gateway
// Provides security verification for AI-generated smart contracts and agent action templates

mod detector;
mod service;
mod report;
mod cli;

pub use detector::{VulnerabilityDetector, SecurityWarning, Severity};
pub use service::{DeploymentGateway, VerificationResult, GatewaySettings};
pub use report::{SecurityReport, SecurityReportGenerator};
pub use cli::run_cli;

// Re-export the main gateway entry point for easy access
pub use service::create_default_gateway;
