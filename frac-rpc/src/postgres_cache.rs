// PostgreSQL L2 Cache Layer
// For recent blocks that don't fit in Redis but are frequently accessed

use anyhow::Result;
use serde_json::Value;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct PostgresCache {
    pool: Arc<PgPool>,
}

impl PostgresCache {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        // Create tables if they don't exist
        Self::init_schema(&pool).await?;

        info!("✅ PostgreSQL L2 cache initialized");

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    async fn init_schema(pool: &PgPool) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS block_cache (
                block_number BIGINT PRIMARY KEY,
                block_data JSONB NOT NULL,
                cached_at TIMESTAMP DEFAULT NOW(),
                access_count INTEGER DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_block_cache_cached_at ON block_cache(cached_at);

            CREATE TABLE IF NOT EXISTS transaction_cache (
                tx_hash TEXT PRIMARY KEY,
                tx_data JSONB NOT NULL,
                block_number BIGINT,
                cached_at TIMESTAMP DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_tx_cache_block ON transaction_cache(block_number);

            CREATE TABLE IF NOT EXISTS receipt_cache (
                tx_hash TEXT PRIMARY KEY,
                receipt_data JSONB NOT NULL,
                block_number BIGINT,
                cached_at TIMESTAMP DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_receipt_cache_block ON receipt_cache(block_number);
            "#
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get block data from PostgreSQL cache
    pub async fn get_block(&self, block_number: u64) -> Result<Option<Value>> {
        let result = sqlx::query_as::<_, (Value,)>(
            "SELECT block_data FROM block_cache WHERE block_number = $1"
        )
        .bind(block_number as i64)
        .fetch_optional(&*self.pool)
        .await?;

        if result.is_some() {
            // Update access count
            let _ = sqlx::query(
                "UPDATE block_cache SET access_count = access_count + 1 WHERE block_number = $1"
            )
            .bind(block_number as i64)
            .execute(&*self.pool)
            .await;

            debug!("PostgreSQL cache hit for block {}", block_number);
        }

        Ok(result.map(|r| r.0))
    }

    /// Cache block data in PostgreSQL
    pub async fn cache_block(&self, block_number: u64, data: &Value) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO block_cache (block_number, block_data)
            VALUES ($1, $2)
            ON CONFLICT (block_number) DO UPDATE
            SET block_data = $2, cached_at = NOW()
            "#
        )
        .bind(block_number as i64)
        .bind(data)
        .execute(&*self.pool)
        .await?;

        debug!("Cached block {} in PostgreSQL", block_number);
        Ok(())
    }

    /// Get transaction data
    pub async fn get_transaction(&self, tx_hash: &str) -> Result<Option<Value>> {
        let result = sqlx::query_as::<_, (Value,)>(
            "SELECT tx_data FROM transaction_cache WHERE tx_hash = $1"
        )
        .bind(tx_hash)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(result.map(|r| r.0))
    }

    /// Cache transaction data
    pub async fn cache_transaction(&self, tx_hash: &str, block_number: u64, data: &Value) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO transaction_cache (tx_hash, block_number, tx_data)
            VALUES ($1, $2, $3)
            ON CONFLICT (tx_hash) DO UPDATE
            SET tx_data = $3, cached_at = NOW()
            "#
        )
        .bind(tx_hash)
        .bind(block_number as i64)
        .bind(data)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Cleanup old entries (run periodically)
    pub async fn cleanup_old_entries(&self, days: i32) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM block_cache 
            WHERE cached_at < NOW() - INTERVAL '$1 days'
            AND access_count < 5
            "#
        )
        .bind(days)
        .execute(&*self.pool)
        .await?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            info!("Cleaned up {} old blocks from PostgreSQL cache", deleted);
        }

        Ok(deleted)
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> Result<PostgresCacheStats> {
        let (total_blocks, total_txs, total_receipts): (i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT 
                (SELECT COUNT(*) FROM block_cache),
                (SELECT COUNT(*) FROM transaction_cache),
                (SELECT COUNT(*) FROM receipt_cache)
            "#
        )
        .fetch_one(&*self.pool)
        .await?;

        let (avg_access_count,): (Option<f64>,) = sqlx::query_as(
            "SELECT AVG(access_count) FROM block_cache"
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(PostgresCacheStats {
            total_blocks: total_blocks as u64,
            total_transactions: total_txs as u64,
            total_receipts: total_receipts as u64,
            avg_access_count: avg_access_count.unwrap_or(0.0),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PostgresCacheStats {
    pub total_blocks: u64,
    pub total_transactions: u64,
    pub total_receipts: u64,
    pub avg_access_count: f64,
}
