// Tauri commands for laptop-friendly features

use crate::AppState;
use crate::laptop_optimizer::{ImpactStats, LaptopProfile};
use crate::optimizer::PowerMode;

#[tauri::command]
pub async fn get_impact_stats(
    state: tauri::State<'_, AppState>
) -> Result<ImpactStats, String> {
    let mut optimizer = state.laptop_optimizer.write().await;
    Ok(optimizer.get_impact_stats())
}

#[tauri::command]
pub async fn update_laptop_profile(
    profile: LaptopProfile,
    state: tauri::State<'_, AppState>
) -> Result<(), String> {
    *state.laptop_profile.write().await = profile.clone();
    *state.laptop_optimizer.write().await = crate::laptop_optimizer::LaptopOptimizer::new(profile);
    Ok(())
}

#[tauri::command]
pub async fn set_power_mode(
    mode: PowerMode,
    state: tauri::State<'_, AppState>
) -> Result<(), String> {
    *state.power_mode.write().await = mode;
    let mut optimizer = state.optimizer.write().await;
    optimizer.set_power_mode(mode);
    Ok(())
}

#[tauri::command]
pub async fn should_prove_now(
    state: tauri::State<'_, AppState>
) -> Result<(bool, String), String> {
    let mut optimizer = state.laptop_optimizer.write().await;
    Ok(optimizer.should_prove())
}

#[tauri::command]
pub async fn get_recommended_settings(
    state: tauri::State<'_, AppState>
) -> Result<RecommendedSettings, String> {
    let mut laptop_opt = state.laptop_optimizer.write().await;
    let mut desktop_opt = state.optimizer.write().await;
    
    let (can_prove, reason) = laptop_opt.should_prove();
    let cpu_limit = laptop_opt.get_cpu_limit();
    let network_limit = laptop_opt.get_network_limit_mbps();
    let system_stats = desktop_opt.get_system_stats();
    
    Ok(RecommendedSettings {
        can_prove,
        pause_reason: if !can_prove { Some(reason) } else { None },
        cpu_limit_percent: cpu_limit,
        network_limit_mbps: network_limit,
        recommended_threads: desktop_opt.get_optimal_threads(),
        recommended_batch_size: desktop_opt.get_optimal_batch_size(),
        system_stats,
    })
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedSettings {
    pub can_prove: bool,
    pub pause_reason: Option<String>,
    pub cpu_limit_percent: f32,
    pub network_limit_mbps: f32,
    pub recommended_threads: usize,
    pub recommended_batch_size: usize,
    pub system_stats: crate::optimizer::SystemStats,
}
