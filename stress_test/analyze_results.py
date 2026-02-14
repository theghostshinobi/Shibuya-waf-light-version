#!/usr/bin/env python3
"""
WAF Stress Test Results Analyzer
================================
Parses attack_log.jsonl and generates vulnerability reports.
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List

def load_attack_log(log_path: Path) -> List[Dict]:
    """Load attack log from JSONL file"""
    entries = []
    with open(log_path, "r") as f:
        for line in f:
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries

def analyze_results(entries: List[Dict]) -> Dict:
    """Analyze attack results and calculate metrics"""
    
    # Initialize category stats
    category_stats = defaultdict(lambda: {
        "total": 0,
        "blocked": 0,
        "passed": 0,
        "errors": 0,
        "bypassed": []
    })
    
    total_blocked = 0
    total_passed = 0
    total_errors = 0
    latencies = []
    
    for entry in entries:
        cat = entry.get("category", "Unknown")
        category_stats[cat]["total"] += 1
        
        if entry.get("blocked"):
            category_stats[cat]["blocked"] += 1
            total_blocked += 1
        elif entry.get("status") and 200 <= entry["status"] < 400:
            category_stats[cat]["passed"] += 1
            total_passed += 1
            category_stats[cat]["bypassed"].append(entry)
        else:
            category_stats[cat]["errors"] += 1
            total_errors += 1
        
        if entry.get("latency_ms"):
            latencies.append(entry["latency_ms"])
    
    # Calculate percentiles
    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.5)] if latencies else 0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0
    p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0
    
    return {
        "total_requests": len(entries),
        "total_blocked": total_blocked,
        "total_passed": total_passed,
        "total_errors": total_errors,
        "block_rate": total_blocked / len(entries) if entries else 0,
        "latency_p50": p50,
        "latency_p95": p95,
        "latency_p99": p99,
        "category_stats": dict(category_stats)
    }

def generate_vulnerability_report(analysis: Dict, output_dir: Path):
    """Generate critical_vulnerabilities.md report"""
    
    cat_stats = analysis["category_stats"]
    total = analysis["total_requests"]
    blocked = analysis["total_blocked"]
    block_rate = analysis["block_rate"] * 100
    
    # Identify critical vulnerabilities (< 70% block rate)
    critical = []
    high = []
    medium = []
    
    for cat, data in cat_stats.items():
        if data["total"] == 0:
            continue
        rate = data["blocked"] / data["total"] * 100
        if rate < 70:
            critical.append((cat, data, rate))
        elif rate < 85:
            high.append((cat, data, rate))
        elif rate < 95:
            medium.append((cat, data, rate))
    
    # Sort by severity (lowest block rate first)
    critical.sort(key=lambda x: x[2])
    high.sort(key=lambda x: x[2])
    
    report = f"""# 🔴 WAF SHIBUYA - CRITICAL VULNERABILITIES REPORT

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## EXECUTIVE SUMMARY

| Metric | Value |
|--------|-------|
| **Total Attacks** | {total:,} |
| **Blocked** | {blocked:,} ({block_rate:.1f}%) |
| **Passed (Bypassed)** | {analysis['total_passed']:,} |
| **Critical Vulnerabilities** | {len(critical)} |
| **High Priority Fixes** | {len(high)} |
| **Medium Priority** | {len(medium)} |

### Overall Block Rate by Category

| Category | Total | Blocked | Passed | Block Rate | Status |
|----------|-------|---------|--------|------------|--------|
"""
    
    for cat, data in sorted(cat_stats.items(), key=lambda x: x[1]["blocked"]/max(x[1]["total"],1)):
        if data["total"] == 0:
            continue
        rate = data["blocked"] / data["total"] * 100
        status = "🔴 CRITICAL" if rate < 70 else "⚠️ HIGH" if rate < 85 else "⚡ MEDIUM" if rate < 95 else "✅ GOOD"
        report += f"| {cat} | {data['total']} | {data['blocked']} | {data['passed']} | {rate:.1f}% | {status} |\n"
    
    report += f"\n---\n\n## 🔴 CRITICAL VULNERABILITIES (Block Rate < 70%)\n\n"
    
    if critical:
        for i, (cat, data, rate) in enumerate(critical, 1):
            bypassed = data["bypassed"][:5]
            report += f"""### CVE-2026-{i:03d}: {cat} Protection Bypass

**Severity**: CRITICAL  
**Block Rate**: {rate:.1f}% ({data['blocked']}/{data['total']} blocked)

**Successful Attack Examples**:
"""
            for bypass in bypassed:
                payload = bypass.get("payload", "")[:80]
                report += f"- `{payload}` → Status {bypass.get('status')}\n"
            
            report += f"""
**Recommended Fix**:
1. Review {cat} detection rules
2. Add more pattern variations to rule set
3. Enable ML-based detection for {cat}
4. Consider paranoia level increase

---

"""
    else:
        report += "> ✅ No critical vulnerabilities detected (all categories above 70% block rate)\n\n"
    
    # High priority
    report += "## ⚠️ HIGH PRIORITY FIXES (Block Rate 70-85%)\n\n"
    
    if high:
        for cat, data, rate in high:
            report += f"- **{cat}**: {rate:.1f}% block rate ({data['passed']} bypassed)\n"
    else:
        report += "> No high priority issues\n"
    
    # Medium priority
    report += "\n## ⚡ MEDIUM PRIORITY (Block Rate 85-95%)\n\n"
    
    if medium:
        for cat, data, rate in medium:
            report += f"- **{cat}**: {rate:.1f}% block rate\n"
    else:
        report += "> No medium priority issues\n"
    
    # Performance
    report += f"""

---

## 📊 PERFORMANCE METRICS

| Metric | Value |
|--------|-------|
| Latency P50 | {analysis['latency_p50']:.1f}ms |
| Latency P95 | {analysis['latency_p95']:.1f}ms |
| Latency P99 | {analysis['latency_p99']:.1f}ms |

---

## 🎯 RECOMMENDED ACTION PLAN

### Week 1 (Critical Fixes)
"""
    
    for i, (cat, data, rate) in enumerate(critical[:3], 1):
        report += f"{i}. Fix {cat} detection (current: {rate:.1f}%)\n"
    
    if len(critical) < 3:
        remaining = 3 - len(critical)
        for i, (cat, data, rate) in enumerate(high[:remaining], len(critical) + 1):
            report += f"{i}. Improve {cat} detection (current: {rate:.1f}%)\n"
    
    report += """
### Week 2 (High Priority)
4. Update CRS rules to latest version
5. Add ML-based detection for obfuscated payloads
6. Review false positive tuning

### Week 3 (Testing)
7. Re-run stress test
8. Target: 95%+ block rate across all categories
9. Validate no regression in false positives
"""
    
    # Top bypassed patterns
    report += "\n---\n\n## 🔓 TOP BYPASSED ATTACK PATTERNS\n\n"
    report += "| Rank | Category | Payload | Status |\n"
    report += "|------|----------|---------|--------|\n"
    
    all_bypassed = []
    for cat, data in cat_stats.items():
        for bypass in data["bypassed"][:10]:
            all_bypassed.append({
                "category": cat,
                "payload": bypass.get("payload", "")[:60],
                "status": bypass.get("status")
            })
    
    for i, bypass in enumerate(all_bypassed[:20], 1):
        payload = bypass["payload"].replace("|", "\\|").replace("\n", " ")
        report += f"| {i} | {bypass['category']} | `{payload}` | {bypass['status']} |\n"
    
    # Write report
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / "critical_vulnerabilities.md"
    with open(report_path, "w") as f:
        f.write(report)
    
    print(f"✅ Generated: {report_path}")
    return report_path

def generate_bypass_report(analysis: Dict, output_dir: Path):
    """Generate detailed bypass_report.md"""
    
    cat_stats = analysis["category_stats"]
    
    report = f"""# WAF Bypass Analysis Report

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Summary

This report details all attack payloads that successfully bypassed WAF protection.

"""
    
    for cat, data in sorted(cat_stats.items()):
        if not data["bypassed"]:
            continue
        
        rate = data["blocked"] / data["total"] * 100 if data["total"] else 0
        report += f"## {cat} ({len(data['bypassed'])} bypassed, {rate:.1f}% block rate)\n\n"
        
        for bypass in data["bypassed"][:20]:
            report += f"- **Status {bypass.get('status')}**: `{bypass.get('payload', '')[:100]}`\n"
        
        if len(data["bypassed"]) > 20:
            report += f"\n*...and {len(data['bypassed']) - 20} more*\n"
        
        report += "\n"
    
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / "bypass_report.md"
    with open(report_path, "w") as f:
        f.write(report)
    
    print(f"✅ Generated: {report_path}")

def generate_roadmap(analysis: Dict, output_dir: Path):
    """Generate fix_priority_roadmap.md"""
    
    cat_stats = analysis["category_stats"]
    
    # Sort categories by priority (lowest block rate first)
    priorities = []
    for cat, data in cat_stats.items():
        if data["total"] > 0:
            rate = data["blocked"] / data["total"] * 100
            priorities.append((cat, rate, data["passed"]))
    
    priorities.sort(key=lambda x: x[1])
    
    report = f"""# WAF Fix Priority Roadmap

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Total Block Rate**: {analysis['block_rate']*100:.1f}%

---

## Priority Matrix

| Priority | Category | Current Block Rate | Bypassed Count | Target |
|----------|----------|-------------------|----------------|--------|
"""
    
    for i, (cat, rate, bypassed) in enumerate(priorities, 1):
        priority = "🔴 P0" if rate < 70 else "🟠 P1" if rate < 85 else "🟡 P2" if rate < 95 else "🟢 P3"
        target = "99%" if rate < 70 else "95%" if rate < 85 else "98%"
        report += f"| {priority} | {cat} | {rate:.1f}% | {bypassed} | {target} |\n"
    
    report += """

---

## Week 1: Critical Fixes

### Day 1-2: Address P0 Issues
"""
    
    p0_items = [p for p in priorities if p[1] < 70]
    for cat, rate, _ in p0_items[:3]:
        report += f"- [ ] Fix {cat} detection (current: {rate:.1f}%)\n"
    
    report += """
### Day 3-4: Rule Updates
- [ ] Update CRS rules to latest version
- [ ] Add custom rules for detected bypass patterns
- [ ] Review and tune paranoia level

### Day 5: Verification
- [ ] Run focused tests on fixed categories
- [ ] Verify no false positive regression

---

## Week 2: High Priority

### Day 1-3: Implement Improvements
"""
    
    p1_items = [p for p in priorities if 70 <= p[1] < 85]
    for cat, rate, _ in p1_items[:3]:
        report += f"- [ ] Improve {cat} detection (current: {rate:.1f}%)\n"
    
    report += """
### Day 4-5: ML Enhancement
- [ ] Enable ML-based detection for obfuscated patterns
- [ ] Train on collected bypass payloads
- [ ] Deploy updated ML model

---

## Week 3: Testing & Validation

- [ ] Full stress test re-run (10,000+ requests)
- [ ] Target: 95%+ overall block rate
- [ ] Document all remaining gaps
- [ ] Update threat intel feeds
- [ ] Final production readiness review
"""
    
    output_dir.mkdir(exist_ok=True)
    report_path = output_dir / "fix_priority_roadmap.md"
    with open(report_path, "w") as f:
        f.write(report)
    
    print(f"✅ Generated: {report_path}")

def main():
    parser = argparse.ArgumentParser(description="Analyze WAF stress test results")
    parser.add_argument("--input", default="attack_log.jsonl", help="Input log file")
    parser.add_argument("--output", default="reports", help="Output directory")
    args = parser.parse_args()
    
    input_path = Path(args.input)
    output_dir = Path(args.output)
    
    if not input_path.exists():
        print(f"❌ Input file not found: {input_path}")
        return
    
    print(f"📊 Analyzing: {input_path}")
    entries = load_attack_log(input_path)
    print(f"   Loaded {len(entries)} entries")
    
    analysis = analyze_results(entries)
    
    print(f"\n📈 Results:")
    print(f"   Block Rate: {analysis['block_rate']*100:.1f}%")
    print(f"   Bypassed: {analysis['total_passed']}")
    
    print(f"\n📝 Generating reports...")
    generate_vulnerability_report(analysis, output_dir)
    generate_bypass_report(analysis, output_dir)
    generate_roadmap(analysis, output_dir)
    
    print(f"\n✅ All reports saved to: {output_dir}")

if __name__ == "__main__":
    main()
