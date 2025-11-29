// Desktop Prover Efficiency Optimizer
// Minimizes resource usage while maximizing earnings

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use sysinfo::System;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum PowerMode {
    /// Maximum performance (high CPU, ignore battery)
    Maximum,
    /// Balanced (recommended, adapts to system)
    Balanced,
    /// Power saver (low CPU, battery-friendly)
    PowerSaver,
    /// Eco mode (minimal CPU, maximum efficiency)
    Eco,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_cpu_percent: f32,
    pub max_memory_mb: u64,
    pub max_threads: usize,
    pub batch_size: usize,
    pub sleep_between_proofs_ms: u64,
}

impl PowerMode {
    pub fn get_limits(&self) -> ResourceLimits {
        match self {
            PowerMode::Maximum => ResourceLimits {
                max_cpu_percent: 95.0,
                max_memory_mb: 4096,
                max_threads: num_cpus::get(),
                batch_size: 10,
                sleep_between_proofs_ms: 0,
            },
            PowerMode::Balanced => ResourceLimits {
                max_cpu_percent: 50.0,
                max_memory_mb: 2048,
                max_threads: num_cpus::get() / 2,
                batch_size: 5,
                sleep_between_proofs_ms: 100,
            },
            PowerMode::PowerSaver => ResourceLimits {
                max_cpu_percent: 25.0,
                max_memory_mb: 1024,
                max_threads: 2,
                batch_size: 2,
                sleep_between_proofs_ms: 500,
            },
            PowerMode::Eco => ResourceLimits {
                max_cpu_percent: 10.0,
                max_memory_mb: 512,
                max_threads: 1,
                batch_size: 1,
                sleep_between_proofs_ms: 2000,
            },
        }
    }
}

pub struct DesktopOptimizer {
    system: System,
    power_mode: PowerMode,
    limits: ResourceLimits,
    
    // Auto-pause triggers
    pause_on_battery: bool,
    pause_battery_threshold: u32,
    pause_on_gaming: bool,
    pause_on_high_cpu: bool,
    high_cpu_threshold: f32,
    
    // Adaptive learning
    last_check: Instant,
    check_interval: Duration,
}

impl DesktopOptimizer {
    pub fn new(power_mode: PowerMode) -> Self {
        let limits = power_mode.get_limits();
        
        Self {
            system: System::new_all(),
            power_mode,
            limits,
            pause_on_battery: true,
            pause_battery_threshold: 20,
            pause_on_gaming: true,
            pause_on_high_cpu: true,
            high_cpu_threshold: 80.0,
            last_check: Instant::now(),
            check_interval: Duration::from_secs(5),
        }
    }
    
    /// Update power mode dynamically
    pub fn set_power_mode(&mut self, mode: PowerMode) {
        self.power_mode = mode;
        self.limits = mode.get_limits();
    }
    
    /// Check if proving should be paused
    pub fn should_pause(&mut self) -> (bool, String) {
        // Rate limit checks
        if self.last_check.elapsed() < self.check_interval {
            return (false, String::new());
        }
        
        self.system.refresh_all();
        self.last_check = Instant::now();
        
        // Check battery
        if self.pause_on_battery {
            #[cfg(target_os = "macos")]
            {
                if let Some(battery) = self.get_battery_level() {
                    if battery < self.pause_battery_threshold {
                        return (true, format!("Battery low ({}%)", battery));
                    }
                }
            }
        }
        
        // Check if gaming or high-load app running
        if self.pause_on_gaming && self.is_gaming() {
            return (true, "Gaming detected".to_string());
        }
        
        // Check system CPU usage
        if self.pause_on_high_cpu {
            let cpu_usage = self.get_total_cpu_usage();
            if cpu_usage > self.high_cpu_threshold {
                return (true, format!("System CPU high ({:.1}%)", cpu_usage));
            }
        }
        
        (false, String::new())
    }
    
    /// Get recommended thread count based on current system load
    pub fn get_optimal_threads(&mut self) -> usize {
        self.system.refresh_cpu();
        
        let cpu_usage = self.get_total_cpu_usage();
        let base_threads = self.limits.max_threads;
        
        // Adaptive: reduce threads if system is busy
        if cpu_usage > 70.0 {
            1 // Minimal when system busy
        } else if cpu_usage > 50.0 {
            base_threads / 2
        } else {
            base_threads
        }
    }
    
    /// Get recommended batch size
    pub fn get_optimal_batch_size(&mut self) -> usize {
        self.system.refresh_memory();
        
        let available_mem = self.system.available_memory() / 1024 / 1024; // Convert to MB
        let base_batch = self.limits.batch_size;
        
        // Reduce batch if memory constrained
        if available_mem < 1000 {
            1
        } else if available_mem < 2000 {
            base_batch / 2
        } else {
            base_batch
        }
    }
    
    /// Sleep between proofs to control resource usage
    pub async fn rate_limit_sleep(&self) {
        if self.limits.sleep_between_proofs_ms > 0 {
            tokio::time::sleep(Duration::from_millis(
                self.limits.sleep_between_proofs_ms
            )).await;
        }
    }
    
    /// Get current system stats
    pub fn get_system_stats(&mut self) -> SystemStats {
        self.system.refresh_all();
        
        SystemStats {
            cpu_usage: self.get_total_cpu_usage(),
            memory_used_mb: (self.system.used_memory() / 1024 / 1024) as u32,
            memory_total_mb: (self.system.total_memory() / 1024 / 1024) as u32,
            battery_level: self.get_battery_level(),
            temperature_celsius: self.get_cpu_temperature(),
        }
    }
    
    // Private helpers
    
    fn get_total_cpu_usage(&self) -> f32 {
        self.system.cpus().iter()
            .map(|cpu| cpu.cpu_usage())
            .sum::<f32>() / self.system.cpus().len() as f32
    }
    
    #[cfg(target_os = "macos")]
    fn get_battery_level(&self) -> Option<u32> {
        use std::process::Command;
        
        let output = Command::new("pmset")
            .args(&["-g", "batt"])
            .output()
            .ok()?;
        
        let output_str = String::from_utf8(output.stdout).ok()?;
        
        // Parse "100%; discharging;" or "75%; AC attached;"
        for line in output_str.lines() {
            if let Some(pct_pos) = line.find('%') {
                if let Some(start) = line[..pct_pos].rfind(char::is_numeric) {
                    if let Some(end) = line[..=start].rfind(|c: char| !c.is_numeric()) {
                        if let Ok(level) = line[end+1..pct_pos].parse::<u32>() {
                            return Some(level);
                        }
                    }
                }
            }
        }
        
        None
    }
    
    #[cfg(not(target_os = "macos"))]
    fn get_battery_level(&self) -> Option<u32> {
        // TODO: Implement for Windows/Linux
        None
    }
    
    fn get_cpu_temperature(&self) -> Option<f32> {
        // TODO: Cross-platform temp reading
        None
    }
    
    fn is_gaming(&self) -> bool {
        // Common game process names
        let game_keywords = [
            "game", "steam", "epic", "unity", "unreal",
            "valorant", "league", "dota", "csgo", "fortnite",
            "minecraft", "wow", "gta", "apex", "overwatch",
        ];
        
        for (_, process) in self.system.processes() {
            let name = process.name().to_lowercase();
            
            // Check if it's a game
            if game_keywords.iter().any(|&kw| name.contains(kw)) {
                // Also check if it's using significant CPU
                if process.cpu_usage() > 20.0 {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Enable/disable auto-pause features
    pub fn set_auto_pause_config(
        &mut self,
        pause_on_battery: bool,
        pause_battery_threshold: u32,
        pause_on_gaming: bool,
        pause_on_high_cpu: bool,
    ) {
        self.pause_on_battery = pause_on_battery;
        self.pause_battery_threshold = pause_battery_threshold;
        self.pause_on_gaming = pause_on_gaming;
        self.pause_on_high_cpu = pause_on_high_cpu;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    pub cpu_usage: f32,
    pub memory_used_mb: u32,
    pub memory_total_mb: u32,
    pub battery_level: Option<u32>,
    pub temperature_celsius: Option<f32>,
}

// Network efficiency optimization
pub struct NetworkOptimizer {
    batch_requests: bool,
    compress_data: bool,
    cache_aggressive: bool,
}

impl NetworkOptimizer {
    pub fn new(power_mode: PowerMode) -> Self {
        match power_mode {
            PowerMode::Maximum => Self {
                batch_requests: false,
                compress_data: false,
                cache_aggressive: false,
            },
            PowerMode::Balanced => Self {
                batch_requests: true,
                compress_data: false,
                cache_aggressive: true,
            },
            PowerMode::PowerSaver | PowerMode::Eco => Self {
                batch_requests: true,
                compress_data: true,
                cache_aggressive: true,
            },
        }
    }
    
    /// Should we batch multiple RPC calls together?
    pub fn should_batch(&self) -> bool {
        self.batch_requests
    }
    
    /// Should we compress network data?
    pub fn should_compress(&self) -> bool {
        self.compress_data
    }
    
    /// Cache aggressiveness level
    pub fn cache_ttl_multiplier(&self) -> f32 {
        if self.cache_aggressive { 2.0 } else { 1.0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_power_modes() {
        let max = PowerMode::Maximum.get_limits();
        let eco = PowerMode::Eco.get_limits();
        
        assert!(max.max_cpu_percent > eco.max_cpu_percent);
        assert!(max.max_threads > eco.max_threads);
        assert!(max.sleep_between_proofs_ms < eco.sleep_between_proofs_ms);
    }
    
    #[tokio::test]
    async fn test_optimizer() {
        let mut opt = DesktopOptimizer::new(PowerMode::Balanced);
        
        let (should_pause, _reason) = opt.should_pause();
        // Should not pause in test environment
        assert!(!should_pause);
        
        let threads = opt.get_optimal_threads();
        assert!(threads > 0);
        assert!(threads <= num_cpus::get());
    }
}
