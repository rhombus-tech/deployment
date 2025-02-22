use ethers::types::H160;

/// Deployment data
#[derive(Clone, Debug, Default)]
pub struct DeploymentData {
    /// Contract owner
    pub owner: H160,
}
