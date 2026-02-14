use anyhow::Result;
use sqlx::postgres::PgPool;
use sqlx::FromRow;
use serde::Serialize;
use super::classification::AttackType;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Serialize, FromRow)]
pub struct FeedbackSample {
    pub request_id: String,
    pub features: String, // JSON serialization of feature vector
    pub actual_class: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub struct FeedbackManager {
    pool: PgPool,
}

impl FeedbackManager {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn init_db(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ml_feedback (
                id SERIAL PRIMARY KEY,
                request_id TEXT NOT NULL,
                predicted_class TEXT NOT NULL,
                actual_class TEXT NOT NULL,
                features TEXT NOT NULL, -- JSON
                comment TEXT,
                used_for_training BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            "#
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }

    pub async fn store_feedback(
        &self,
        request_id: &str,
        predicted_class: AttackType,
        actual_class: AttackType,
        features_json: &str,
        comment: Option<String>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO ml_feedback (request_id, predicted_class, actual_class, features, comment)
            VALUES ($1, $2, $3, $4, $5)
            "#
        )
        .bind(request_id)
        .bind(predicted_class.name())
        .bind(actual_class.name())
        .bind(features_json)
        .bind(comment)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }

    pub async fn get_pending_feedback(&self, limit: i64) -> Result<Vec<FeedbackSample>> {
        let samples = sqlx::query_as::<_, FeedbackSample>(
            r#"
            SELECT request_id, features, actual_class, created_at
            FROM ml_feedback
            WHERE used_for_training = FALSE
            LIMIT $1
            "#
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        
        Ok(samples)
    }

    pub async fn mark_as_used(&self, request_ids: &[String]) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE ml_feedback
            SET used_for_training = TRUE
            WHERE request_id = ANY($1)
            "#
        )
        .bind(request_ids)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }

    pub async fn trigger_retrain(&self) -> Result<()> {
        // 1. Export samples
        let samples = self.get_pending_feedback(1000).await?;
        if samples.is_empty() {
            return Ok(());
        }

        let export_path = "ml/datasets/feedback_samples.jsonl";
        let mut file = File::create(export_path)?;
        
        for sample in &samples {
            // Need to reshape into what training script expects
            // Training script expects specific keys e.g. "label", "features" (array) or raw req.
            // If we stored raw features array (28 floats), we can assume logic to parse it.
            // Let's assume features column stores [0.1, 0.5, ...]
            
            let line = serde_json::json!({
                "label": sample.actual_class,
                "features": serde_json::from_str::<Vec<f32>>(&sample.features).unwrap_or_default()
            });
            writeln!(file, "{}", line)?;
        }

        // 2. Trigger python script
        // In real world we might just send a signal or use a job queue.
        // Here we spawn process.
        std::process::Command::new("python")
            .arg("ml/training/retrain.py") 
            .spawn()?;

        // 3. Mark as used
        let ids: Vec<String> = samples.iter().map(|s| s.request_id.clone()).collect();
        self.mark_as_used(&ids).await?;

        Ok(())
    }
}
