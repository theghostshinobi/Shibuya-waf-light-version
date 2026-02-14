# ============================================
# Stage 1: Builder
# ============================================
FROM rust:1.92-slim as builder

WORKDIR /build

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    perl \
    make \
    cmake \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifests first (caching)
# Copy dependency manifests first (caching)
COPY Cargo.toml Cargo.lock ./
COPY core/Cargo.toml core/
COPY cli/Cargo.toml cli/
COPY api/Cargo.toml api/
COPY launcher/Cargo.toml launcher/

# Create dummy source to cache dependencies
RUN mkdir -p core/src cli/src api/src launcher/src core/benches && \
    echo "fn main() {}" > core/src/main.rs && \
    echo "fn main() {}" > cli/src/main.rs && \
    echo "fn main() {}" > launcher/src/main.rs && \
    echo "fn main() {}" > core/benches/rule_matching.rs && \
    touch api/src/lib.rs && \
    cargo build --release && \
    rm -rf core/src cli/src api/src launcher/src core/benches

# Copy actual source code
COPY . .

# Build release binary
RUN cargo build --release --bin waf-killer

# ============================================
# Stage 2: Runtime (Distroless)
# ============================================
FROM gcr.io/distroless/cc-debian12:nonroot

# Copy binary from builder
COPY --from=builder /build/target/release/waf-killer /usr/local/bin/shibuya-waf

# Copy config and models
COPY --from=builder /build/config /etc/shibuya/config
COPY --from=builder /build/ml/models /etc/shibuya/models

# Use non-root user (distroless provides user 65532)
USER 65532:65532

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/shibuya-waf", "health"]

# Expose ports
EXPOSE 8443 9090

# Run WAF
ENTRYPOINT ["/usr/local/bin/shibuya-waf"]
CMD ["start"]
