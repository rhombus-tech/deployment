use crate::bytecode::SecurityFinding;

pub struct IoTOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl IoTOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SecurityFinding> {
        self.detect()
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_sensor_spoofing() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "IoT sensor data can be spoofed without validation at PC {}. \
                    Physical sensor manipulation can inject false data into smart contracts.",
                    pc
                ),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_device_authentication_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "IoT device authentication insufficient at PC {}. \
                    Unauthorized devices can submit oracle data.",
                    pc
                ),
                pc,
                confidence: 0.84,
            });
        }

        if let Some(pc) = self.detect_data_freshness_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "IoT oracle data lacks freshness validation at PC {}. \
                    Stale or replayed sensor readings can be used maliciously.",
                    pc
                ),
                pc,
                confidence: 0.82,
            });
        }

        findings
    }

    fn detect_sensor_spoofing(&self) -> Option<usize> {
        // Look for IoT data ingestion without integrity checks
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // submitSensorData, updateReading, reportMeasurement selectors
                if matches!(selector, [0xa1, 0x3e, _, _] | [0xb2, 0x4f, _, _] | [0xc3, 0x5d, _, _]) {
                    let mut accepts_sensor_data = false;
                    let mut validates_signature = false;
                    let mut checks_data_range = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check if accepting sensor measurements
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (sensor value)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x55 { // SSTORE (storing directly)
                                accepts_sensor_data = true;
                            }
                        }
                        
                        // Check for cryptographic signature validation
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x60 && // PUSH1 0x01 (ecrecover)
                               self.bytecode[j + 1] == 0x01 &&
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0xfa { // STATICCALL
                                validates_signature = true;
                            }
                        }
                        
                        // Check for range/sanity checks
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (value)
                               j + 4 < self.bytecode.len() &&
                               (self.bytecode[j + 3] == 0x10 || self.bytecode[j + 3] == 0x11) && // LT/GT
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO (bounds check)
                                checks_data_range = true;
                            }
                        }
                    }
                    
                    if accepts_sensor_data && !validates_signature && !checks_data_range {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_device_authentication_bypass(&self) -> Option<usize> {
        // Look for device registration without proper authentication
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // registerDevice, authorizeSensor, addOracle selectors
                if matches!(selector, [0xd1, 0x3e, _, _] | [0xe2, 0x4f, _, _] | [0xf3, 0x5c, _, _]) {
                    let mut registers_device = false;
                    let mut validates_device_id = false;
                    let mut requires_attestation = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check if registering device address
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (device addr)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x55 { // SSTORE (whitelisting)
                                registers_device = true;
                            }
                        }
                        
                        // Check for device ID validation
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (device ID)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x20 && // KECCAK256
                               j + 7 < self.bytecode.len() &&
                               self.bytecode[j + 6] == 0x54 { // SLOAD (checking registry)
                                validates_device_id = true;
                            }
                        }
                        
                        // Check for hardware attestation
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (attestation)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x60 && // PUSH1 0x01 (ecrecover)
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0xfa { // STATICCALL
                                requires_attestation = true;
                            }
                        }
                    }
                    
                    if registers_device && !validates_device_id && !requires_attestation {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_data_freshness_vulnerability(&self) -> Option<usize> {
        // Look for sensor data usage without timestamp validation
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // getSensorData, readValue, fetchMeasurement selectors
                if matches!(selector, [0xa2, 0x3e, _, _] | [0xb3, 0x4f, _, _] | [0xc4, 0x5d, _, _]) {
                    let mut loads_sensor_data = false;
                    let mut checks_timestamp = false;
                    let mut validates_sequence = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check if loading sensor data
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (sensor value)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0xf3 { // RETURN
                                loads_sensor_data = true;
                            }
                        }
                        
                        // Check for timestamp freshness validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x03 && // SUB
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x10 { // LT (max age check)
                                checks_timestamp = true;
                            }
                        }
                        
                        // Check for sequence number anti-replay
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (last sequence)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x35 && // CALLDATALOAD (new sequence)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x10 { // LT (must be greater)
                                validates_sequence = true;
                            }
                        }
                    }
                    
                    if loads_sensor_data && !checks_timestamp && !validates_sequence {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
