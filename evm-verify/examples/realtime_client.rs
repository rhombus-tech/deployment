use anyhow::Result;
use clap::{Arg, Command};
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::{sleep, interval};
use tracing::{info, warn, error};

/// Example client for interacting with the real-time zkEVM API
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    // Parse command line arguments
    let matches = Command::new("Real-time zkEVM Client")
        .version("1.0.0")
        .author("Windsurf Engineering Team")
        .about("Example client for real-time zkEVM transaction validation API")
        .arg(
            Arg::new("server")
                .short('s')
                .long("server")
                .value_name("URL")
                .help("Server base URL")
                .default_value("http://localhost:8080"),
        )
        .arg(
            Arg::new("websocket-url")
                .short('w')
                .long("websocket-url")
                .value_name("WS_URL")
                .help("Ethereum WebSocket URL")
                .default_value("wss://eth-mainnet.ws.alchemyapi.io/v2/demo"),
        )
        .arg(
            Arg::new("workers")
                .long("workers")
                .value_name("COUNT")
                .help("Number of worker threads")
                .default_value("4"),
        )
        .arg(
            Arg::new("target-latency")
                .long("target-latency")
                .value_name("MS")
                .help("Target latency in milliseconds")
                .default_value("100"),
        )
        .arg(
            Arg::new("optimization-level")
                .long("optimization-level")
                .value_name("LEVEL")
                .help("Circuit optimization level (0-3)")
                .default_value("2"),
        )
        .arg(
            Arg::new("enable-mev")
                .long("enable-mev")
                .help("Enable MEV protection")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("demo-mode")
                .long("demo")
                .help("Run in demonstration mode with automated lifecycle")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let server_url = matches.get_one::<String>("server").unwrap();
    let websocket_url = matches.get_one::<String>("websocket-url").unwrap();
    let workers: usize = matches.get_one::<String>("workers").unwrap().parse()?;
    let target_latency: u64 = matches.get_one::<String>("target-latency").unwrap().parse()?;
    let optimization_level: u8 = matches.get_one::<String>("optimization-level").unwrap().parse()?;
    let enable_mev = matches.get_flag("enable-mev");
    let demo_mode = matches.get_flag("demo-mode");

    let client = Client::new();

    info!("🚀 Real-time zkEVM Client Starting");
    info!("   Server: {}", server_url);
    info!("   WebSocket: {}", websocket_url);
    info!("   Workers: {}", workers);
    info!("   Target Latency: {}ms", target_latency);
    info!("   Optimization Level: {}", optimization_level);
    info!("   MEV Protection: {}", enable_mev);

    // Step 1: Check server health
    check_server_health(&client, server_url).await?;

    if demo_mode {
        // Run automated demonstration
        run_demo(&client, server_url, websocket_url, workers, target_latency, optimization_level, enable_mev).await?;
    } else {
        // Interactive mode
        run_interactive(&client, server_url, websocket_url, workers, target_latency, optimization_level, enable_mev).await?;
    }

    info!("✅ Client completed successfully");
    Ok(())
}

/// Check server health before starting
async fn check_server_health(client: &Client, server_url: &str) -> Result<()> {
    info!("🔍 Checking server health...");
    
    let health_url = format!("{}/health", server_url);
    
    match client.get(&health_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                let health: Value = response.json().await?;
                info!("✅ Server is healthy: {}", health.get("status").unwrap_or(&json!("unknown")));
                
                if let Some(uptime) = health.get("uptime") {
                    info!("   Uptime: {} seconds", uptime);
                }
            } else {
                error!("❌ Server health check failed with status: {}", response.status());
                return Err(anyhow::anyhow!("Server not healthy"));
            }
        }
        Err(e) => {
            error!("❌ Failed to connect to server: {}", e);
            return Err(anyhow::anyhow!("Cannot connect to server"));
        }
    }

    Ok(())
}

/// Run automated demonstration
async fn run_demo(
    client: &Client,
    server_url: &str,
    websocket_url: &str,
    workers: usize,
    target_latency: u64,
    optimization_level: u8,
    enable_mev: bool,
) -> Result<()> {
    info!("🎯 Starting automated demonstration");

    // Start real-time processing
    let start_response = start_realtime_processing(
        client, server_url, websocket_url, workers, target_latency, optimization_level, enable_mev
    ).await?;

    info!("✅ Real-time processing started with instance ID: {}", 
        start_response.get("instance_id").unwrap_or(&json!("unknown")));

    // Monitor for 60 seconds
    info!("📊 Monitoring real-time processing for 60 seconds...");
    let mut interval_timer = interval(Duration::from_secs(10));
    let mut iterations = 0;

    while iterations < 6 { // 6 * 10 seconds = 60 seconds
        interval_timer.tick().await;
        
        match get_realtime_status(client, server_url, true).await {
            Ok(status) => {
                display_status(&status);
            }
            Err(e) => {
                warn!("Failed to get status: {}", e);
            }
        }
        
        iterations += 1;
    }

    // Stop processing
    info!("🛑 Stopping real-time processing...");
    let stop_response = stop_realtime_processing(client, server_url).await?;
    
    if let Some(final_stats) = stop_response.get("final_stats") {
        info!("📈 Final Statistics:");
        if let Some(total) = final_stats.get("total_processed") {
            info!("   Total Processed: {}", total);
        }
        if let Some(latency) = final_stats.get("avg_latency_ms") {
            info!("   Average Latency: {}ms", latency);
        }
        if let Some(success_rate) = final_stats.get("success_rate") {
            info!("   Success Rate: {}%", success_rate);
        }
    }

    info!("🎉 Demonstration completed successfully!");
    Ok(())
}

/// Run interactive mode
async fn run_interactive(
    client: &Client,
    server_url: &str,
    websocket_url: &str,
    workers: usize,
    target_latency: u64,
    optimization_level: u8,
    enable_mev: bool,
) -> Result<()> {
    info!("🖥️  Interactive mode - follow the prompts");

    println!("\n=== Real-time zkEVM Processing Demo ===");
    println!("1. Starting real-time processing...");
    
    // Start processing
    let start_response = start_realtime_processing(
        client, server_url, websocket_url, workers, target_latency, optimization_level, enable_mev
    ).await?;

    if start_response.get("success").unwrap_or(&json!(false)).as_bool().unwrap_or(false) {
        println!("✅ Real-time processing started successfully!");
        
        if let Some(instance_id) = start_response.get("instance_id") {
            println!("   Instance ID: {}", instance_id);
        }
    } else {
        println!("❌ Failed to start real-time processing");
        if let Some(error) = start_response.get("error") {
            println!("   Error: {}", error);
        }
        return Ok(());
    }

    println!("\n2. Monitoring status (press Ctrl+C to stop)...");
    
    // Monitor status
    let mut interval_timer = interval(Duration::from_secs(5));
    
    loop {
        tokio::select! {
            _ = interval_timer.tick() => {
                match get_realtime_status(client, server_url, true).await {
                    Ok(status) => {
                        display_status_compact(&status);
                    }
                    Err(e) => {
                        warn!("Status check failed: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n\n3. Stopping real-time processing...");
                break;
            }
        }
    }

    // Stop processing
    match stop_realtime_processing(client, server_url).await {
        Ok(stop_response) => {
            if stop_response.get("success").unwrap_or(&json!(false)).as_bool().unwrap_or(false) {
                println!("✅ Real-time processing stopped successfully!");
                
                if let Some(final_stats) = stop_response.get("final_stats") {
                    println!("\n📊 Final Statistics:");
                    display_final_stats(final_stats);
                }
            } else {
                println!("❌ Failed to stop real-time processing");
                if let Some(error) = stop_response.get("error") {
                    println!("   Error: {}", error);
                }
            }
        }
        Err(e) => {
            error!("Failed to stop processing: {}", e);
        }
    }

    Ok(())
}

/// Start real-time processing
async fn start_realtime_processing(
    client: &Client,
    server_url: &str,
    websocket_url: &str,
    workers: usize,
    target_latency: u64,
    optimization_level: u8,
    enable_mev: bool,
) -> Result<Value> {
    let start_url = format!("{}/api/v1/realtime/start", server_url);
    
    let request_body = json!({
        "websocket_url": websocket_url,
        "processing_mode": "latest",
        "target_latency_ms": target_latency,
        "worker_count": workers,
        "max_queue_size": 1000,
        "enable_mev_protection": enable_mev,
        "fallback_strategy": "skip",
        "optimization_level": optimization_level,
        "enable_batching": true,
        "batch_size": 10
    });

    let response = client
        .post(&start_url)
        .json(&request_body)
        .send()
        .await?;

    if response.status().is_success() {
        Ok(response.json().await?)
    } else {
        let error_text = response.text().await?;
        Err(anyhow::anyhow!("Start request failed: {}", error_text))
    }
}

/// Get real-time processing status
async fn get_realtime_status(client: &Client, server_url: &str, include_details: bool) -> Result<Value> {
    let mut status_url = format!("{}/api/v1/realtime/status", server_url);
    
    if include_details {
        status_url.push_str("?include_workers=true&include_circuits=true&include_metrics=true");
    }

    let response = client.get(&status_url).send().await?;

    if response.status().is_success() {
        Ok(response.json().await?)
    } else {
        let error_text = response.text().await?;
        Err(anyhow::anyhow!("Status request failed: {}", error_text))
    }
}

/// Stop real-time processing
async fn stop_realtime_processing(client: &Client, server_url: &str) -> Result<Value> {
    let stop_url = format!("{}/api/v1/realtime/stop", server_url);
    
    let response = client.post(&stop_url).send().await?;

    if response.status().is_success() {
        Ok(response.json().await?)
    } else {
        let error_text = response.text().await?;
        Err(anyhow::anyhow!("Stop request failed: {}", error_text))
    }
}

/// Display detailed status information
fn display_status(status: &Value) {
    println!("\n📊 === Real-time Processing Status ===");
    
    if let Some(status_obj) = status.get("status") {
        if let Some(is_running) = status_obj.get("is_running") {
            println!("🔄 Running: {}", is_running);
        }
        
        if let Some(instance_id) = status_obj.get("instance_id") {
            println!("🆔 Instance: {}", instance_id);
        }

        if let Some(metrics) = status_obj.get("metrics") {
            println!("📈 Metrics:");
            if let Some(total) = metrics.get("total_processed") {
                println!("   Total Processed: {}", total);
            }
            if let Some(recent) = metrics.get("recent_processed") {
                println!("   Recent (1min): {}", recent);
            }
            if let Some(avg_latency) = metrics.get("avg_latency_ms") {
                println!("   Avg Latency: {:.1}ms", avg_latency.as_f64().unwrap_or(0.0));
            }
            if let Some(success_rate) = metrics.get("success_rate") {
                println!("   Success Rate: {:.1}%", success_rate.as_f64().unwrap_or(0.0));
            }
            if let Some(tps) = metrics.get("tps") {
                println!("   TPS: {:.2}", tps.as_f64().unwrap_or(0.0));
            }
            if let Some(queue_size) = metrics.get("queue_size") {
                println!("   Queue Size: {}", queue_size);
            }
        }

        if let Some(ws_status) = status_obj.get("websocket_status") {
            if let Some(connected) = ws_status.get("connected") {
                let status_icon = if connected.as_bool().unwrap_or(false) { "✅" } else { "❌" };
                println!("🌐 WebSocket: {} {}", status_icon, connected);
            }
        }

        if let Some(circuit_status) = status_obj.get("circuit_status") {
            if let Some(ready) = circuit_status.get("ready") {
                let status_icon = if ready.as_bool().unwrap_or(false) { "✅" } else { "⚠️" };
                println!("🔧 Circuits: {} {}", status_icon, ready);
            }
        }
    }

    if let Some(health) = status.get("health") {
        if let Some(score) = health.get("score") {
            let score_val = score.as_u64().unwrap_or(0);
            let health_icon = if score_val >= 80 { "💚" } else if score_val >= 60 { "💛" } else { "❤️" };
            println!("💊 Health: {} {}%", health_icon, score_val);
        }
    }
}

/// Display compact status for frequent updates
fn display_status_compact(status: &Value) {
    if let Some(status_obj) = status.get("status") {
        if let Some(metrics) = status_obj.get("metrics") {
            let total = metrics.get("total_processed").unwrap_or(&json!(0)).as_u64().unwrap_or(0);
            let latency = metrics.get("avg_latency_ms").unwrap_or(&json!(0.0)).as_f64().unwrap_or(0.0);
            let success_rate = metrics.get("success_rate").unwrap_or(&json!(0.0)).as_f64().unwrap_or(0.0);
            let tps = metrics.get("tps").unwrap_or(&json!(0.0)).as_f64().unwrap_or(0.0);
            
            print!("\r📊 Processed: {} | Latency: {:.1}ms | Success: {:.1}% | TPS: {:.2}     ", 
                total, latency, success_rate, tps);
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        }
    }
}

/// Display final statistics
fn display_final_stats(stats: &Value) {
    if let Some(total) = stats.get("total_processed") {
        println!("   📦 Total Transactions: {}", total);
    }
    if let Some(latency) = stats.get("avg_latency_ms") {
        println!("   ⏱️  Average Latency: {:.1}ms", latency.as_f64().unwrap_or(0.0));
    }
    if let Some(success_rate) = stats.get("success_rate") {
        println!("   ✅ Success Rate: {:.1}%", success_rate.as_f64().unwrap_or(0.0));
    }
    if let Some(uptime) = stats.get("uptime_info") {
        println!("   🕐 Session Duration: {}", uptime);
    }
}
