// Laptop-Specific Optimizations
// Ensures minimal impact on user experience

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use sysinfo::System;
use chrono::Timelike;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaptopProfile {
    // Battery awareness
    pub pause_on_battery: bool,
    pub battery_pause_threshold: u32,  // Pause below this %
    pub battery_slow_threshold: u32,    // Slow down below this %
    pub plugged_in_only: bool,
    
    // Thermal management
    pub enable_thermal_throttle: bool,
    pub max_temperature_celsius: f32,
    pub fan_noise_prevention: bool,
    
    // Network limits
    pub max_network_mbps: f32,
    pub pause_on_metered: bool,
    pub pause_on_video_call: bool,
    
    // Schedule
    pub schedule_enabled: bool,
    pub active_hours_start: u8,  // 0-23
    pub active_hours_end: u8,
    pub idle_only: bool,
    pub idle_minutes_threshold: u32,
}

impl Default for LaptopProfile {
    fn default() -> Self {
        Self {
            // Conservative defaults for laptops
            pause_on_battery: true,
            battery_pause_threshold: 20,
            battery_slow_threshold: 50,
            plugged_in_only: false,
            
            enable_thermal_throttle: true,
            max_temperature_celsius: 80.0,
            fan_noise_prevention: true,
            
            max_network_mbps: 5.0,  // Very conservative
            pause_on_metered: true,
            pause_on_video_call: true,
            
            schedule_enabled: false,
            active_hours_start: 2,  // 2 AM
            active_hours_end: 6,    // 6 AM
            idle_only: false,
            idle_minutes_threshold: 30,
        }
    }
}

pub struct LaptopOptimizer {
    profile: LaptopProfile,
    system: System,
    
    // State tracking
    last_input_time: Instant,
    last_network_check: Instant,
    network_usage_history: Vec<(Instant, u64)>,
    temperature_history: Vec<f32>,
    
    // Detection
    is_on_battery: bool,
    current_temperature: Option<f32>,
    is_video_call_active: bool,
    is_on_metered_connection: bool,
}

impl LaptopOptimizer {
    pub fn new(profile: LaptopProfile) -> Self {
        Self {
            profile,
            system: System::new_all(),
            last_input_time: Instant::now(),
            last_network_check: Instant::now(),
            network_usage_history: Vec::new(),
            temperature_history: Vec::new(),
            is_on_battery: false,
            current_temperature: None,
            is_video_call_active: false,
            is_on_metered_connection: false,
        }
    }
    
    /// Main check - should we be proving right now?
    pub fn should_prove(&mut self) -> (bool, String) {
        self.system.refresh_all();
        
        // Check battery status
        if let Some((can_prove, reason)) = self.check_battery() {
            if !can_prove {
                return (false, reason);
            }
        }
        
        // Check thermal status
        if self.profile.enable_thermal_throttle {
            if let Some((can_prove, reason)) = self.check_temperature() {
                if !can_prove {
                    return (false, reason);
                }
            }
        }
        
        // Check schedule
        if self.profile.schedule_enabled {
            if !self.is_in_active_hours() {
                return (false, "Outside scheduled proving hours".to_string());
            }
        }
        
        // Check idle status
        if self.profile.idle_only {
            if !self.is_system_idle() {
                return (false, "System not idle".to_string());
            }
        }
        
        // Check network conditions
        if self.profile.pause_on_video_call && self.detect_video_call() {
            return (false, "Video call detected".to_string());
        }
        
        if self.profile.pause_on_metered && self.is_metered_connection() {
            return (false, "Metered connection detected".to_string());
        }
        
        (true, String::new())
    }
    
    /// Get recommended CPU limit based on conditions
    pub fn get_cpu_limit(&mut self) -> f32 {
        let mut limit: f32 = 50.0; // Base limit for laptops
        
        // Battery adjustments
        if self.is_on_battery {
            if let Some(battery_level) = self.get_battery_level() {
                if battery_level < self.profile.battery_slow_threshold {
                    limit = limit.min(25.0); // 25% when battery low
                } else {
                    limit = limit.min(35.0); // 35% when on battery
                }
            }
        }
        
        // Temperature adjustments
        if let Some(temp) = self.current_temperature {
            if temp > self.profile.max_temperature_celsius {
                limit = limit.min(10.0); // Emergency throttle
            } else if temp > self.profile.max_temperature_celsius - 5.0 {
                limit = limit.min(30.0); // Preventive throttle
            }
        }
        
        // Fan noise prevention (reduce when fans are spinning)
        if self.profile.fan_noise_prevention && self.are_fans_active() {
            limit = limit.min(40.0);
        }
        
        limit
    }
    
    /// Get network bandwidth limit
    pub fn get_network_limit_mbps(&self) -> f32 {
        let base_limit = self.profile.max_network_mbps;
        
        // Further reduce on battery
        if self.is_on_battery {
            base_limit * 0.5
        } else {
            base_limit
        }
    }
    
    /// Get system impact statistics
    pub fn get_impact_stats(&mut self) -> ImpactStats {
        self.system.refresh_all();
        
        let cpu_usage = self.get_prover_cpu_usage();
        let memory_mb = self.get_prover_memory_mb();
        let network_mbps = self.get_current_network_mbps();
        
        ImpactStats {
            cpu_percent: cpu_usage,
            memory_mb,
            network_mbps,
            battery_impact_minutes: self.estimate_battery_impact(cpu_usage),
            temperature_celsius: self.current_temperature,
            is_throttled: cpu_usage < 30.0,
            throttle_reason: self.get_throttle_reason(),
        }
    }
    
    // Private helper methods
    
    fn check_battery(&mut self) -> Option<(bool, String)> {
        if !self.profile.pause_on_battery && !self.profile.plugged_in_only {
            return None; // Battery checks disabled
        }
        
        let battery_level = self.get_battery_level()?;
        let is_charging = self.is_charging();
        
        self.is_on_battery = !is_charging;
        
        if self.profile.plugged_in_only && !is_charging {
            return Some((false, "Only prove when plugged in (user setting)".to_string()));
        }
        
        if battery_level < self.profile.battery_pause_threshold {
            return Some((false, format!("Battery low ({}%)", battery_level)));
        }
        
        None
    }
    
    fn check_temperature(&mut self) -> Option<(bool, String)> {
        let temp = self.get_cpu_temperature()?;
        self.current_temperature = Some(temp);
        self.temperature_history.push(temp);
        
        // Keep last 10 readings
        if self.temperature_history.len() > 10 {
            self.temperature_history.remove(0);
        }
        
        if temp > self.profile.max_temperature_celsius {
            return Some((false, format!("CPU too hot ({:.1}°C)", temp)));
        }
        
        None
    }
    
    fn is_in_active_hours(&self) -> bool {
        use chrono::Local;
        let now = Local::now();
        let current_hour = now.hour() as u8;
        
        let start = self.profile.active_hours_start;
        let end = self.profile.active_hours_end;
        
        if start < end {
            current_hour >= start && current_hour < end
        } else {
            // Wraps around midnight (e.g., 22:00 - 06:00)
            current_hour >= start || current_hour < end
        }
    }
    
    fn is_system_idle(&mut self) -> bool {
        let idle_duration = self.get_system_idle_duration();
        let threshold = Duration::from_secs(self.profile.idle_minutes_threshold as u64 * 60);
        
        idle_duration > threshold
    }
    
    fn get_system_idle_duration(&self) -> Duration {
        // Check for recent user input
        // TODO: Platform-specific idle detection
        self.last_input_time.elapsed()
    }
    
    fn detect_video_call(&mut self) -> bool {
        // Detect video conferencing apps
        let video_app_keywords = [
            "zoom", "teams", "meet", "skype", "webex", "discord",
            "slack", "facetime", "hangouts", "bluejeans",
        ];
        
        for (_pid, process) in self.system.processes() {
            let name = process.name().to_lowercase();
            
            // Check if it's a video app
            if video_app_keywords.iter().any(|&kw| name.contains(kw)) {
                // Check if it's using significant resources (actual call vs idle)
                if process.cpu_usage() > 5.0 {
                    self.is_video_call_active = true;
                    return true;
                }
            }
        }
        
        self.is_video_call_active = false;
        false
    }
    
    fn is_metered_connection(&mut self) -> bool {
        // TODO: Detect cellular/metered connections
        // For now, check network name/type
        self.is_on_metered_connection
    }
    
    fn get_battery_level(&self) -> Option<u32> {
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            
            let output = Command::new("pmset")
                .args(&["-g", "batt"])
                .output()
                .ok()?;
            
            let output_str = String::from_utf8(output.stdout).ok()?;
            
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
        }
        
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            let output = Command::new("WMIC")
                .args(&["Path", "Win32_Battery", "Get", "EstimatedChargeRemaining"])
                .output()
                .ok()?;
            
            let output_str = String::from_utf8(output.stdout).ok()?;
            
            for line in output_str.lines() {
                if let Ok(level) = line.trim().parse::<u32>() {
                    return Some(level);
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            // Try to read from /sys/class/power_supply/BAT0/capacity
            if let Ok(content) = fs::read_to_string("/sys/class/power_supply/BAT0/capacity") {
                if let Ok(level) = content.trim().parse::<u32>() {
                    return Some(level);
                }
            }
        }
        
        None
    }
    
    fn is_charging(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            
            if let Ok(output) = Command::new("pmset").args(&["-g", "batt"]).output() {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    return output_str.contains("AC Power");
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            
            if let Ok(output) = Command::new("WMIC")
                .args(&["Path", "Win32_Battery", "Get", "BatteryStatus"])
                .output()
            {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    // BatteryStatus: 2 = charging
                    return output_str.contains("2");
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            if let Ok(content) = fs::read_to_string("/sys/class/power_supply/BAT0/status") {
                return content.trim() == "Charging" || content.trim() == "Full";
            }
        }
        
        true // Assume plugged in if can't detect
    }
    
    fn get_cpu_temperature(&self) -> Option<f32> {
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            
            // Try powermetrics
            if let Ok(output) = Command::new("sudo")
                .args(&["powermetrics", "--samplers", "smc", "-i1", "-n1"])
                .output()
            {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    for line in output_str.lines() {
                        if line.contains("CPU die temperature") {
                            if let Some(temp_str) = line.split_whitespace().nth(3) {
                                if let Ok(temp) = temp_str.parse::<f32>() {
                                    return Some(temp);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            
            // Try reading from thermal zones
            for i in 0..10 {
                let path = format!("/sys/class/thermal/thermal_zone{}/temp", i);
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(temp_millidegrees) = content.trim().parse::<f32>() {
                        return Some(temp_millidegrees / 1000.0);
                    }
                }
            }
        }
        
        None
    }
    
    fn are_fans_active(&self) -> bool {
        // Heuristic: If CPU temp is high, fans are likely active
        if let Some(temp) = self.current_temperature {
            temp > 60.0
        } else {
            false
        }
    }
    
    fn get_prover_cpu_usage(&self) -> f32 {
        let current_pid = std::process::id();
        
        if let Some(process) = self.system.process(sysinfo::Pid::from_u32(current_pid)) {
            process.cpu_usage()
        } else {
            0.0
        }
    }
    
    fn get_prover_memory_mb(&self) -> u32 {
        let current_pid = std::process::id();
        
        if let Some(process) = self.system.process(sysinfo::Pid::from_u32(current_pid)) {
            (process.memory() / 1024 / 1024) as u32
        } else {
            0
        }
    }
    
    fn get_current_network_mbps(&mut self) -> f32 {
        // Network monitoring removed in sysinfo 0.30
        // Would need separate crate for network stats
        let total_bytes = 0u64;
        
        let now = Instant::now();
        self.network_usage_history.push((now, total_bytes));
        
        // Keep last 5 seconds of history
        self.network_usage_history.retain(|(time, _)| time.elapsed() < Duration::from_secs(5));
        
        if self.network_usage_history.len() < 2 {
            return 0.0;
        }
        
        let oldest = &self.network_usage_history[0];
        let newest = self.network_usage_history.last().unwrap();
        
        let duration_secs = (newest.0 - oldest.0).as_secs_f32();
        let bytes_diff = newest.1.saturating_sub(oldest.1);
        
        if duration_secs > 0.0 {
            (bytes_diff as f32 / duration_secs) / 125_000.0 // Convert to Mbps
        } else {
            0.0
        }
    }
    
    fn estimate_battery_impact(&self, cpu_percent: f32) -> Option<i32> {
        if !self.is_on_battery {
            return None;
        }
        
        // Rough estimate: Each 10% CPU usage costs ~20 minutes of battery
        let impact_minutes = (cpu_percent / 10.0 * 20.0) as i32;
        
        Some(-impact_minutes)
    }
    
    fn get_throttle_reason(&self) -> Option<String> {
        if self.is_on_battery {
            return Some("On battery power".to_string());
        }
        
        if let Some(temp) = self.current_temperature {
            if temp > self.profile.max_temperature_celsius - 5.0 {
                return Some(format!("High temperature ({:.1}°C)", temp));
            }
        }
        
        if self.is_video_call_active {
            return Some("Video call active".to_string());
        }
        
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactStats {
    pub cpu_percent: f32,
    pub memory_mb: u32,
    pub network_mbps: f32,
    pub battery_impact_minutes: Option<i32>,
    pub temperature_celsius: Option<f32>,
    pub is_throttled: bool,
    pub throttle_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_profile() {
        let profile = LaptopProfile::default();
        assert!(profile.pause_on_battery);
        assert_eq!(profile.battery_pause_threshold, 20);
    }
    
    #[test]
    fn test_active_hours() {
        let mut profile = LaptopProfile::default();
        profile.schedule_enabled = true;
        profile.active_hours_start = 9;
        profile.active_hours_end = 17;
        
        let optimizer = LaptopOptimizer::new(profile);
        // Would need to mock time for proper testing
    }
}
