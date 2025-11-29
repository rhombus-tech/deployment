// Geographic Routing for Multi-Region Deployment
// Routes requests to nearest region based on IP geolocation

use anyhow::Result;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info};

#[derive(Clone, Debug)]
pub struct GeoRouter {
    regions: Vec<Region>,
}

#[derive(Clone, Debug)]
pub struct Region {
    pub name: String,
    pub location: GeoLocation,
    pub endpoints: Vec<String>,
    pub priority: u8, // 1 = primary, 2 = secondary, etc.
}

#[derive(Clone, Debug, PartialEq)]
pub enum GeoLocation {
    UsEast,
    UsWest,
    EuWest,
    EuCentral,
    AsiaPacific,
    Global, // Fallback for any location
}

impl GeoRouter {
    pub fn new(regions: Vec<Region>) -> Self {
        info!("✅ Geographic router initialized with {} regions", regions.len());
        Self { regions }
    }

    /// Get the best region for a given client IP
    pub fn get_best_region(&self, client_ip: Option<IpAddr>) -> Option<&Region> {
        if let Some(ip) = client_ip {
            let location = self.geolocate_ip(ip);
            debug!("Client IP {:?} → {:?}", ip, location);

            // Find matching region
            let matching = self.regions
                .iter()
                .filter(|r| r.location == location)
                .min_by_key(|r| r.priority);

            if matching.is_some() {
                return matching;
            }
        }

        // Fallback: return primary region
        self.regions
            .iter()
            .min_by_key(|r| r.priority)
    }

    /// Simple IP geolocation (in production, use MaxMind GeoIP2 or similar)
    fn geolocate_ip(&self, ip: IpAddr) -> GeoLocation {
        // This is a simplified version
        // In production, use a proper GeoIP database like MaxMind GeoIP2

        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                
                // North America (simplified ranges)
                if octets[0] >= 3 && octets[0] <= 76 {
                    return GeoLocation::UsEast;
                }
                
                // Europe (simplified ranges)
                if octets[0] >= 77 && octets[0] <= 95 {
                    return GeoLocation::EuWest;
                }
                
                // Asia Pacific (simplified ranges)
                if octets[0] >= 96 && octets[0] <= 223 {
                    return GeoLocation::AsiaPacific;
                }
                
                GeoLocation::Global
            }
            IpAddr::V6(_) => {
                // IPv6 geolocation would go here
                GeoLocation::Global
            }
        }
    }

    /// Get all available regions sorted by priority
    pub fn get_regions_by_priority(&self) -> Vec<&Region> {
        let mut regions: Vec<&Region> = self.regions.iter().collect();
        regions.sort_by_key(|r| r.priority);
        regions
    }

    /// Get fallback regions if primary fails
    pub fn get_fallback_regions(&self, current_region: &Region) -> Vec<&Region> {
        self.regions
            .iter()
            .filter(|r| r.name != current_region.name)
            .collect()
    }
}

/// Configuration for multi-region setup
pub fn create_default_regions() -> Vec<Region> {
    vec![
        Region {
            name: "us-east-1".to_string(),
            location: GeoLocation::UsEast,
            endpoints: vec![
                "http://us-east-rpc.frac.network:8545".to_string(),
            ],
            priority: 1, // Primary
        },
        Region {
            name: "eu-west-1".to_string(),
            location: GeoLocation::EuWest,
            endpoints: vec![
                "http://eu-west-rpc.frac.network:8545".to_string(),
            ],
            priority: 2, // Secondary
        },
        Region {
            name: "asia-1".to_string(),
            location: GeoLocation::AsiaPacific,
            endpoints: vec![
                "http://asia-rpc.frac.network:8545".to_string(),
            ],
            priority: 3, // Tertiary
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_geolocation() {
        let router = GeoRouter::new(create_default_regions());
        
        // Test US IP
        let us_ip = IpAddr::from_str("8.8.8.8").unwrap();
        let region = router.get_best_region(Some(us_ip));
        assert!(region.is_some());
        assert_eq!(region.unwrap().name, "us-east-1");
    }

    #[test]
    fn test_fallback() {
        let router = GeoRouter::new(create_default_regions());
        let region = router.get_best_region(None);
        assert!(region.is_some());
        assert_eq!(region.unwrap().priority, 1); // Should return primary
    }
}
