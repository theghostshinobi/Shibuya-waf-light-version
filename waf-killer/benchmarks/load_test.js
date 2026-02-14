// =============================================================================
// SHIBUYA WAF — k6 Load Test Suite
// Usage: k6 run benchmarks/load_test.js -e SCENARIO=default
// =============================================================================
import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// ── Custom Metrics ──────────────────────────────────────────────────────────
const blockRate     = new Rate('waf_block_rate');
const attackBlocked = new Counter('waf_attack_blocked');
const attackBypassed = new Counter('waf_attack_bypassed');
const cleanLatency  = new Trend('waf_clean_latency', true);
const attackLatency = new Trend('waf_attack_latency', true);

// ── Configuration ───────────────────────────────────────────────────────────
const HTTP_PORT  = __ENV.K6_WAF_HTTP_PORT  || '8080';
const ADMIN_PORT = __ENV.K6_WAF_ADMIN_PORT || '9090';
const BASE_URL   = `http://localhost:${HTTP_PORT}`;
const ADMIN_URL  = `http://localhost:${ADMIN_PORT}`;
const SCENARIO   = __ENV.SCENARIO || 'default';

// ── Scenarios ───────────────────────────────────────────────────────────────
const scenarios = {
  // Full default run (~3 minutes)
  default: {
    sustained:  { executor: 'constant-arrival-rate', rate: 5000,  duration: '60s',  preAllocatedVUs: 200, maxVUs: 500,  exec: 'cleanTraffic',  startTime: '0s'   },
    spike:      { executor: 'ramping-arrival-rate',  startRate: 100, stages: [{ target: 15000, duration: '30s' }, { target: 100, duration: '10s' }], preAllocatedVUs: 200, maxVUs: 800, exec: 'cleanTraffic', startTime: '65s' },
    mixed:      { executor: 'constant-arrival-rate', rate: 2000,  duration: '30s',  preAllocatedVUs: 100, maxVUs: 300,  exec: 'mixedPayloads', startTime: '110s' },
    attacks:    { executor: 'constant-arrival-rate', rate: 500,   duration: '20s',  preAllocatedVUs: 50,  maxVUs: 100,  exec: 'attackPayloads', startTime: '145s' },
  },
  // Quick sanity run (~30 seconds)
  quick: {
    sustained:  { executor: 'constant-arrival-rate', rate: 1000,  duration: '10s',  preAllocatedVUs: 50,  maxVUs: 100,  exec: 'cleanTraffic',   startTime: '0s'  },
    attacks:    { executor: 'constant-arrival-rate', rate: 200,   duration: '10s',  preAllocatedVUs: 20,  maxVUs: 50,   exec: 'attackPayloads', startTime: '15s' },
  },
  // Long stability run (~10 minutes)
  stability: {
    sustained:  { executor: 'constant-arrival-rate', rate: 500,   duration: '600s', preAllocatedVUs: 50,  maxVUs: 100,  exec: 'cleanTraffic', startTime: '0s' },
  },
};

export const options = {
  scenarios: scenarios[SCENARIO] || scenarios['default'],
  thresholds: {
    http_req_duration:     ['p(50)<5', 'p(95)<15', 'p(99)<30'],
    http_req_failed:       ['rate<0.05'],
    waf_clean_latency:     ['p(95)<10'],
    waf_attack_latency:    ['p(95)<20'],
  },
  noConnectionReuse: false,
  insecureSkipTLSVerify: true,
};

// ── Test Data ───────────────────────────────────────────────────────────────

const CLEAN_PATHS = [
  '/api/users',
  '/api/products?category=electronics&price=100',
  '/api/search?q=hello+world',
  '/api/health',
  '/assets/logo.png',
  '/api/orders/12345',
  '/api/settings',
  '/api/notifications',
  '/api/dashboard',
  '/api/profile',
];

const SQLI_PAYLOADS = [
  "1' OR '1'='1",
  "1%27%20OR%20%271%27%3D%271",
  "1' UNI/**/ON SEL/**/ECT",
  "1' OR 1=1--",
  "1' AND 1=0 UNION ALL SELECT NULL,NULL--",
  "admin'--",
  "' or '1'='1'/*",
  "1' WAITFOR DELAY '00:00:05'--",
  "1' AND SLEEP(5)--",
  "1' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
];

const XSS_PAYLOADS = [
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "<svg onload=alert(1)>",
  "javascript:alert(1)",
  '<iframe src="javascript:alert(1)">',
  "<body onload=alert(1)>",
  "<input onfocus=alert(1) autofocus>",
  "<ScRiPt>alert(1)</sCrIpT>",
  "%3Cscript%3Ealert(1)%3C/script%3E",
  "&lt;script&gt;alert(1)&lt;/script&gt;",
];

const PATH_TRAVERSAL = [
  "../../etc/passwd",
  "....//....//etc/passwd",
  "..%2F..%2Fetc%2Fpasswd",
  "..\\..\\etc\\passwd",
  "/etc/passwd%00.jpg",
];

function randomItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function makeJsonBody(sizeBytes) {
  const base = { user: "benchuser", action: "test", timestamp: Date.now() };
  const padding = "x".repeat(Math.max(0, sizeBytes - JSON.stringify(base).length - 20));
  base.data = padding;
  return JSON.stringify(base);
}

// ── Scenario Executors ────────────────────────────────────────────────────

// Scenario 1 & 2: Clean traffic (GET requests)
export function cleanTraffic() {
  const path = randomItem(CLEAN_PATHS);
  const res = http.get(`${BASE_URL}${path}`, { tags: { type: 'clean' } });
  cleanLatency.add(res.timings.duration);
  check(res, {
    'clean: status is not 5xx': (r) => r.status < 500,
  });
}

// Scenario 3: Mixed GET/POST with varying body sizes
export function mixedPayloads() {
  const roll = Math.random();
  if (roll < 0.4) {
    // GET request
    const path = randomItem(CLEAN_PATHS);
    http.get(`${BASE_URL}${path}`, { tags: { type: 'mixed_get' } });
  } else if (roll < 0.7) {
    // POST with 1KB body
    const body = makeJsonBody(1024);
    http.post(`${BASE_URL}/api/data`, body, {
      headers: { 'Content-Type': 'application/json' },
      tags: { type: 'mixed_post_1k' },
    });
  } else if (roll < 0.9) {
    // POST with 10KB body
    const body = makeJsonBody(10240);
    http.post(`${BASE_URL}/api/data`, body, {
      headers: { 'Content-Type': 'application/json' },
      tags: { type: 'mixed_post_10k' },
    });
  } else {
    // POST with 100KB body
    const body = makeJsonBody(102400);
    http.post(`${BASE_URL}/api/data`, body, {
      headers: { 'Content-Type': 'application/json' },
      tags: { type: 'mixed_post_100k' },
    });
  }
}

// Scenario 4: Attack payloads (expect blocks)
export function attackPayloads() {
  const roll = Math.random();
  let payload, attackType;

  if (roll < 0.45) {
    payload = randomItem(SQLI_PAYLOADS);
    attackType = 'sqli';
  } else if (roll < 0.85) {
    payload = randomItem(XSS_PAYLOADS);
    attackType = 'xss';
  } else {
    payload = randomItem(PATH_TRAVERSAL);
    attackType = 'path_traversal';
  }

  // Send as query parameter
  const res = http.get(`${BASE_URL}/api/search?q=${encodeURIComponent(payload)}`, {
    tags: { type: 'attack', attack: attackType },
  });

  attackLatency.add(res.timings.duration);

  const blocked = res.status === 403 || res.status === 406 || res.status === 418;
  blockRate.add(blocked);

  if (blocked) {
    attackBlocked.add(1);
  } else {
    attackBypassed.add(1);
  }

  check(res, {
    'attack: should be blocked (403/406/418)': (r) => r.status === 403 || r.status === 406 || r.status === 418,
  });
}

// ── Lifecycle ────────────────────────────────────────────────────────────────
export function setup() {
  // Verify WAF is reachable
  const healthRes = http.get(`${ADMIN_URL}/health`);
  check(healthRes, {
    'setup: WAF health OK': (r) => r.status === 200,
  });
  if (healthRes.status !== 200) {
    console.error('WAF health check failed — aborting');
    throw new Error('WAF not reachable');
  }
  console.log(`WAF healthy. Starting benchmark: scenario=${SCENARIO}`);
  return { startTime: Date.now() };
}

export function teardown(data) {
  const elapsed = ((Date.now() - data.startTime) / 1000).toFixed(1);
  console.log(`Benchmark complete in ${elapsed}s`);
}
