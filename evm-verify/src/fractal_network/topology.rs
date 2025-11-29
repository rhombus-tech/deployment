// Fractal Network Topology with φ-Optimization

use super::phi_optimizer::{PHI, PHI_INVERSE};

#[derive(Debug, Clone, Hash, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProverID(pub String);

#[derive(Debug, Clone)]
pub struct PhiCoordinates {
    pub fractal_level: u8,
    pub cluster_position: u16,
    pub phi_x: f64,
    pub phi_y: f64,
    pub phi_z: f64,
}

#[derive(Debug)]
pub struct FractalConnection {
    pub target: ProverID,
    pub connection_type: ConnectionType,
    pub bandwidth_weight: f64,
    pub phi_efficiency: f64,
}

#[derive(Debug, Clone)]
pub enum ConnectionType {
    LocalCluster,      // High bandwidth, 5-8 nodes in local cluster
    Hierarchical,      // Medium bandwidth, parent/child connections
    RandomShortcut,    // Low bandwidth, small-world connectivity
    BackupPath,        // Redundancy for fault tolerance
}

impl PhiCoordinates {
    pub fn new(level: u8, position: u16, x: f64, y: f64, z: f64) -> Self {
        Self {
            fractal_level: level,
            cluster_position: position,
            phi_x: x,
            phi_y: y,
            phi_z: z,
        }
    }

    pub fn calculate_parent_coordinates(&self) -> PhiCoordinates {
        PhiCoordinates {
            fractal_level: self.fractal_level.saturating_sub(1),
            cluster_position: (self.cluster_position as f64 / PHI) as u16,
            phi_x: self.phi_x / PHI,
            phi_y: self.phi_y / PHI,
            phi_z: self.phi_z / PHI,
        }
    }

    pub fn calculate_child_coordinates(&self, child_index: u8) -> PhiCoordinates {
        PhiCoordinates {
            fractal_level: self.fractal_level + 1,
            cluster_position: (self.cluster_position as f64 * PHI + child_index as f64) as u16,
            phi_x: self.phi_x * PHI + child_index as f64 * PHI_INVERSE,
            phi_y: self.phi_y * PHI + child_index as f64 * PHI_INVERSE,
            phi_z: self.phi_z * PHI,
        }
    }

    pub fn calculate_phi_distance(&self, other: &PhiCoordinates) -> f64 {
        let dx = self.phi_x - other.phi_x;
        let dy = self.phi_y - other.phi_y;
        let dz = self.phi_z - other.phi_z;
        
        // φ-weighted distance calculation
        (dx.powi(2) * PHI + dy.powi(2) * PHI + dz.powi(2)).sqrt()
    }

    pub fn calculate_phi_efficiency(&self, target: &PhiCoordinates) -> f64 {
        // Calculate efficiency based on φ-distance and network position
        let distance = self.calculate_phi_distance(target);
        let level_efficiency = PHI.powf(-(target.fractal_level as f64));
        
        (PHI / (1.0 + distance)) * level_efficiency
    }
}

impl FractalConnection {
    pub fn new(target: ProverID, connection_type: ConnectionType, coordinates: &PhiCoordinates, target_coordinates: &PhiCoordinates) -> Self {
        let bandwidth_weight = match connection_type {
            ConnectionType::LocalCluster => PHI * PHI,     // Highest bandwidth
            ConnectionType::Hierarchical => PHI,           // High bandwidth
            ConnectionType::RandomShortcut => PHI_INVERSE * PHI_INVERSE, // Low bandwidth
            ConnectionType::BackupPath => PHI_INVERSE,     // Medium bandwidth
        };

        Self {
            target,
            connection_type,
            bandwidth_weight,
            phi_efficiency: coordinates.calculate_phi_efficiency(target_coordinates),
        }
    }

    pub fn is_efficient(&self) -> bool {
        self.phi_efficiency > PHI_INVERSE
    }
}

#[derive(Debug)]
pub struct TopologyManager {
    pub local_connections: Vec<FractalConnection>,
    pub hierarchical_connections: Vec<FractalConnection>,
    pub shortcut_connections: Vec<FractalConnection>,
    pub backup_connections: Vec<FractalConnection>,
}

impl TopologyManager {
    pub fn new() -> Self {
        Self {
            local_connections: Vec::new(),
            hierarchical_connections: Vec::new(),
            shortcut_connections: Vec::new(),
            backup_connections: Vec::new(),
        }
    }

    pub fn add_connection(&mut self, connection: FractalConnection) {
        match connection.connection_type {
            ConnectionType::LocalCluster => self.local_connections.push(connection),
            ConnectionType::Hierarchical => self.hierarchical_connections.push(connection),
            ConnectionType::RandomShortcut => self.shortcut_connections.push(connection),
            ConnectionType::BackupPath => self.backup_connections.push(connection),
        }
    }

    pub fn optimize_connections(&mut self) {
        // Remove inefficient connections
        self.local_connections.retain(|conn| conn.is_efficient());
        self.hierarchical_connections.retain(|conn| conn.is_efficient());
        self.shortcut_connections.retain(|conn| conn.is_efficient());
        self.backup_connections.retain(|conn| conn.is_efficient());
    }

    pub fn get_all_connections(&self) -> Vec<&FractalConnection> {
        let mut all_connections = Vec::new();
        all_connections.extend(&self.local_connections);
        all_connections.extend(&self.hierarchical_connections);
        all_connections.extend(&self.shortcut_connections);
        all_connections.extend(&self.backup_connections);
        all_connections
    }

    pub fn connection_count(&self) -> usize {
        self.local_connections.len() + 
        self.hierarchical_connections.len() + 
        self.shortcut_connections.len() + 
        self.backup_connections.len()
    }
}
