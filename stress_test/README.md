# Shibuya WAF Red Team Stress Test

This directory contains a suite of tools to stress test the Shibuya WAF.

## Prerequisites
- Docker & Docker Compose
- Python 3 + `aiohttp`

## Setup

1. **Start the Environment**
   This spins up the Vulnerable App and the Shibuya WAF (configured to protect the app).
   ```bash
   cd stress_test
   docker-compose -f docker-compose-redteam.yml up --build -d
   ```
   *Note: This might take a few minutes to build the WAF container.*
   *Ensure the WAF is up by checking `http://localhost:9090/health` (metrics/mgmt port usually on 9091 or inside, but traffic on 9090).*

2. **Prepare the Attacker**
   Install dependencies:
   ```bash
   pip install aiohttp
   ```

## Running the Attack

Run the stress test script:
```bash
python3 red_team_stress_test.py --target http://localhost:9090 --duration 60
```

## Reports
A `stress_test_report.json` file will be generated containing:
- Total requests sent/blocked/passed
- Latency metrics (P50, P95, P99)
- List of bypassed payloads

## Architecture
- **Attacker**: Python script (Host)
- **WAF**: Shibuya (Docker Container on port 9090)
- **Target**: Vulnerable Flask App (Docker Container on internal port 8080)
