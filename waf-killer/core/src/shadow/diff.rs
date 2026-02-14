// core/src/shadow/diff.rs

use crate::shadow::{DecisionDiff, ShadowSummary};
use crate::telemetry::{SHADOW_EXECUTIONS_TOTAL, SHADOW_NEW_BLOCKS_TOTAL, SHADOW_NEW_ALLOWS_TOTAL};
use sqlx::PgPool;
use anyhow::Result;

pub struct DiffRecorder {
    db: PgPool,
}

impl DiffRecorder {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn record(&self, diff: DecisionDiff) -> Result<()> {
        // 1. Update Prometheus metrics
        SHADOW_EXECUTIONS_TOTAL.inc();
        
        if diff.action_changed {
            if diff.new_blocks {
                SHADOW_NEW_BLOCKS_TOTAL.inc();
            }
            if diff.new_allows {
                SHADOW_NEW_ALLOWS_TOTAL.inc();
            }
        }
        
        // 2. Store in database (only if decision changed to save space)
        if diff.action_changed {
            sqlx::query(
                "INSERT INTO shadow_diffs 
                 (request_id, production_action, shadow_action, 
                  production_score, shadow_score, diff_data, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, NOW())"
            )
            .bind(&diff.request_id)
            .bind(format!("{:?}", diff.production_action))
            .bind(format!("{:?}", diff.shadow_action))
            .bind(diff.production_score)
            .bind(diff.shadow_score)
            .bind(serde_json::to_value(&diff)?)
            .execute(&self.db)
            .await?;
        }
        
        Ok(())
    }
    
    pub async fn get_summary(&self, range_hours: i32) -> Result<ShadowSummary> {
        let row = sqlx::query(
            r#"SELECT 
               COUNT(*) as total_shadowed,
               SUM(CASE WHEN production_action != shadow_action THEN 1 ELSE 0 END) as action_diffs,
               SUM(CASE WHEN production_action = 'Allow' AND shadow_action = 'Block' THEN 1 ELSE 0 END) as new_blocks,
               SUM(CASE WHEN production_action = 'Block' AND shadow_action = 'Allow' THEN 1 ELSE 0 END) as new_allows,
               COALESCE(AVG(shadow_score - production_score)::float8, 0.0) as avg_score_delta
             FROM shadow_diffs
             WHERE created_at > NOW() - ($1 * INTERVAL '1 hour')"#
        )
        .bind(range_hours as f64)
        .fetch_one(&self.db)
        .await?;
        
        let summary = ShadowSummary {
            total_shadowed: sqlx::Row::get(&row, "total_shadowed"),
            action_diffs: sqlx::Row::get(&row, "action_diffs"),
            new_blocks: sqlx::Row::get(&row, "new_blocks"),
            new_allows: sqlx::Row::get(&row, "new_allows"),
            avg_score_delta: sqlx::Row::get(&row, "avg_score_delta"),
        };
        
        Ok(summary)
    }
}
