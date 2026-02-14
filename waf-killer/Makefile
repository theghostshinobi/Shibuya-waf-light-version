# Testing targets
.PHONY: test test-unit test-waf test-quick

test: test-unit test-waf

test-unit:
	cargo test --all

test-waf:
	@echo "🧪 Running full GoTestWAF scan..."
	@./scripts/run_gotestwaf.sh

test-quick:
	@echo "⚡ Running quick WAF test..."
	@WAF_URL=https://localhost:8443 ./scripts/run_gotestwaf.sh --testCase=sqli,xss

# View latest report
report:
	@LATEST=$$(ls -t tests/gotestwaf/reports/*.html | head -1); \
	if [ -n "$$LATEST" ]; then \
		open "$$LATEST"; \
	else \
		echo "No reports found. Run: make test-waf"; \
	fi
