use anyhow::Result;
use prometheus::{
    Encoder, Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder,
};
use tracing::info;
use tracing_subscriber::{
    layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry as TracingRegistry, Layer,
};
use tokio::sync::broadcast;
use tracing::Event;

// Global log broadcaster
lazy_static::lazy_static! {
    pub static ref LOG_BROADCAST: (broadcast::Sender<LogEntry>, broadcast::Receiver<LogEntry>) = broadcast::channel(100);
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

// Global metrics registry
lazy_static::lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    // Metrics definitions
    pub static ref WAF_REQUESTS_TOTAL: IntCounter = IntCounter::new(
        "waf_requests_total",
        "Total number of requests processed"
    ).unwrap();

    pub static ref WAF_REQUEST_DURATION_SECONDS: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "waf_request_duration_seconds",
            "Request duration in seconds"
        )
    ).unwrap();

    pub static ref WAF_UPSTREAM_CONNECTIONS_ACTIVE: IntGauge = IntGauge::new(
        "waf_upstream_connections_active",
        "Active connections to upstream"
    ).unwrap();

    pub static ref WAF_UPSTREAM_CONNECTIONS_IDLE: IntGauge = IntGauge::new(
        "waf_upstream_connections_idle",
        "Idle connections to upstream"
    ).unwrap();

    pub static ref WAF_UPSTREAM_HEALTH_STATUS: Gauge = Gauge::new(
        "waf_upstream_health_status",
        "Upstream health status (1=healthy, 0=unhealthy)"
    ).unwrap();

    pub static ref SHADOW_EXECUTIONS_TOTAL: IntCounter = IntCounter::new(
        "shadow_executions_total",
        "Total number of shadow policy executions"
    ).unwrap();

    pub static ref SHADOW_NEW_BLOCKS_TOTAL: IntCounter = IntCounter::new(
        "shadow_new_blocks_total",
        "Total number of requests that would be blocked by shadow policy but were allowed by production"
    ).unwrap();

    pub static ref SHADOW_NEW_ALLOWS_TOTAL: IntCounter = IntCounter::new(
        "shadow_new_allows_total",
        "Total number of requests that would be allowed by shadow policy but were blocked by production"
    ).unwrap();

    pub static ref SHADOW_LATENCY_SECONDS: Histogram = Histogram::with_opts(
        HistogramOpts::new(
            "shadow_latency_seconds",
            "Latency of shadow policy execution in seconds"
        )
    ).unwrap();
}

// Custom Tracing Layer for Broadcasting
struct BroadcastLayer;

impl<S> Layer<S> for BroadcastLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target().starts_with("waf_killer") {
            let level = event.metadata().level().to_string();
            let timestamp = chrono::Local::now().to_rfc3339();
            
            let mut visitor = MessageVisitor::new();
            event.record(&mut visitor);
            
            let entry = LogEntry {
                timestamp,
                level,
                message: visitor.message,
            };
            
            let _ = LOG_BROADCAST.0.send(entry);
        }
    }
}

struct MessageVisitor {
    message: String,
}

impl MessageVisitor {
    fn new() -> Self {
        Self { message: String::new() }
    }
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            // Include other fields as JSON if needed, but for now just basic message
             if !self.message.is_empty() {
                self.message.push_str(" ");
            }
            self.message.push_str(&format!("{}={:?}", field.name(), value));
        }
    }
    
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
             self.message = value.to_string();
        } else {
             if !self.message.is_empty() {
                self.message.push_str(" ");
            }
            self.message.push_str(&format!("{}={}", field.name(), value));
        }
    }
}

pub struct Telemetry;

impl Telemetry {
    pub fn init(log_level: &str, log_format: &str) -> Result<()> {
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

        let subscriber = TracingRegistry::default().with(filter);

        if log_format.eq_ignore_ascii_case("json") {
            // Json format requires feature "json" which might be missing. 
            // Fallback to default for Ep 1.
            subscriber
                // .with(tracing_subscriber::fmt::layer().json())
                .with(tracing_subscriber::fmt::layer())
                .with(BroadcastLayer)
                .init();
        } else {
            subscriber
                .with(tracing_subscriber::fmt::layer())
                .with(BroadcastLayer)
                .init();
        }

        // Register metrics
        REGISTRY.register(Box::new(WAF_REQUESTS_TOTAL.clone()))?;
        REGISTRY.register(Box::new(WAF_REQUEST_DURATION_SECONDS.clone()))?;
        REGISTRY.register(Box::new(WAF_UPSTREAM_CONNECTIONS_ACTIVE.clone()))?;
        REGISTRY.register(Box::new(WAF_UPSTREAM_CONNECTIONS_IDLE.clone()))?;
        REGISTRY.register(Box::new(WAF_UPSTREAM_HEALTH_STATUS.clone()))?;
        REGISTRY.register(Box::new(SHADOW_EXECUTIONS_TOTAL.clone()))?;
        REGISTRY.register(Box::new(SHADOW_NEW_BLOCKS_TOTAL.clone()))?;
        REGISTRY.register(Box::new(SHADOW_NEW_ALLOWS_TOTAL.clone()))?;
        REGISTRY.register(Box::new(SHADOW_LATENCY_SECONDS.clone()))?;

        info!(
            "Telemetry initialized (level: {}, format: {})",
            log_level, log_format
        );
        Ok(())
    }

    pub fn gather_metrics() -> String {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = REGISTRY.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}
