<div align="center">

# ⚡ ShadowStrike

### AI-Powered Advanced Security Testing Platform

<br/>

<a href="https://github.com/Hafiz380/shadowstrike"><img src="https://img.shields.io/badge/GitHub-Hafiz380/shadowstrike-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"></a>
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=for-the-badge" alt="License"></a>
<a href="#"><img src="https://img.shields.io/badge/Python-3.12+-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>

</div>

> **ShadowStrike** is an advanced AI-powered security testing platform built on top of [Strix](https://github.com/Hafiz380/shadowstrike). It combines autonomous AI hacking agents with static analysis, memory systems, exploit chaining, and professional reporting — all in one tool.

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/Hafiz380/shadowstrike.git
cd shadowstrike

# Install with advanced features
pip install -e ".[advanced]"

# Verify installation
strix-advanced info
```

## ⚡ What's Inside

ShadowStrike includes **everything from Strix** plus these advanced capabilities:
- **Auto-fix & reporting** to accelerate remediation


<br>


<div align="center">
  <a href="https://shadowstrike.dev">
    <img src=".github/screenshot.png" alt="Strix Demo" width="1000" style="border-radius: 16px;">
  </a>
</div>


## Use Cases

- **Application Security Testing** - Detect and validate critical vulnerabilities in your applications
- **Rapid Penetration Testing** - Get penetration tests done in hours, not weeks, with compliance reports
- **Bug Bounty Automation** - Automate bug bounty research and generate PoCs for faster reporting
- **CI/CD Integration** - Run tests in CI/CD to block vulnerabilities before reaching production

## 🚀 Quick Start

**Prerequisites:**
- Docker (running)
- An LLM API key from any [supported provider](https://docs.shadowstrike.dev/llm-providers/overview) (OpenAI, Anthropic, Google, etc.)

### Installation & First Scan

```bash
# Install Strix
curl -sSL https://shadowstrike.dev/install | bash

# Configure your AI provider
export STRIX_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# Run your first security assessment
strix --target ./app-directory
```

> [!NOTE]
> First run automatically pulls the sandbox Docker image. Results are saved to `strix_runs/<run-name>`

---

## ☁️ Strix Platform

Try the Strix full-stack security platform at **[app.shadowstrike.dev](https://app.shadowstrike.dev)** - sign up for free, connect your repos and domains, and launch a pentest in minutes.

- **Validated findings with PoCs** and reproduction steps
- **One-click autofix** as ready-to-merge pull requests
- **Continuous monitoring** across code, cloud, and infrastructure
- **Integrations** with GitHub, Slack, Jira, Linear, and CI/CD pipelines
- **Continuous learning** that builds on past findings and remediations

[**Start your first pentest →**](https://app.shadowstrike.dev)

---

## ✨ Features

### Agentic Security Tools

Strix agents come equipped with a comprehensive security testing toolkit:

- **Full HTTP Proxy** - Full request/response manipulation and analysis
- **Browser Automation** - Multi-tab browser for testing of XSS, CSRF, auth flows
- **Terminal Environments** - Interactive shells for command execution and testing
- **Python Runtime** - Custom exploit development and validation
- **Reconnaissance** - Automated OSINT and attack surface mapping
- **Code Analysis** - Static and dynamic analysis capabilities
- **Knowledge Management** - Structured findings and attack documentation

### Comprehensive Vulnerability Detection

Strix can identify and validate a wide range of security vulnerabilities:

- **Access Control** - IDOR, privilege escalation, auth bypass
- **Injection Attacks** - SQL, NoSQL, command injection
- **Server-Side** - SSRF, XXE, deserialization flaws
- **Client-Side** - XSS, prototype pollution, DOM vulnerabilities
- **Business Logic** - Race conditions, workflow manipulation
- **Authentication** - JWT vulnerabilities, session management
- **Infrastructure** - Misconfigurations, exposed services

### Graph of Agents

Advanced multi-agent orchestration for comprehensive security testing:

- **Distributed Workflows** - Specialized agents for different attacks and assets
- **Scalable Testing** - Parallel execution for fast comprehensive coverage
- **Dynamic Coordination** - Agents collaborate and share discoveries

---

## Usage Examples

### Basic Usage

```bash
# Scan a local codebase
strix --target ./app-directory

# Security review of a GitHub repository
strix --target https://github.com/org/repo

# Black-box web application assessment
strix --target https://your-app.com
```

### Advanced Testing Scenarios

```bash
# Grey-box authenticated testing
strix --target https://your-app.com --instruction "Perform authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
strix -t https://github.com/org/app -t https://your-app.com

# White-box source-aware scan (local repository)
strix --target ./app-directory --scan-mode standard

# Focused testing with custom instructions
strix --target api.your-app.com --instruction "Focus on business logic flaws and IDOR vulnerabilities"

# Provide detailed instructions through file (e.g., rules of engagement, scope, exclusions)
strix --target api.your-app.com --instruction-file ./instruction.md

# Force PR diff-scope against a specific base branch
strix -n --target ./ --scan-mode quick --scope-mode diff --diff-base origin/main
```

### Headless Mode

Run Strix programmatically without interactive UI using the `-n/--non-interactive` flag-perfect for servers and automated jobs. The CLI prints real-time vulnerability findings, and the final report before exiting. Exits with non-zero code when vulnerabilities are found.

```bash
strix -n --target https://your-app.com
```

### CI/CD (GitHub Actions)

Strix can be added to your pipeline to run a security test on pull requests with a lightweight GitHub Actions workflow:

```yaml
name: strix-penetration-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install Strix
        run: curl -sSL https://shadowstrike.dev/install | bash

      - name: Run Strix
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}

        run: strix -n -t ./ --scan-mode quick
```

> [!TIP]
> In CI pull request runs, Strix automatically scopes quick reviews to changed files.
> If diff-scope cannot resolve, ensure checkout uses full history (`fetch-depth: 0`) or pass
> `--diff-base` explicitly.

### Configuration

```bash
export STRIX_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# Optional
export LLM_API_BASE="your-api-base-url"  # if using a local model, e.g. Ollama, LMStudio
export PERPLEXITY_API_KEY="your-api-key"  # for search capabilities
export STRIX_REASONING_EFFORT="high"  # control thinking effort (default: high, quick scan: medium)
```

> [!NOTE]
> Strix automatically saves your configuration to `~/.strix/cli-config.json`, so you don't have to re-enter it on every run.

**Recommended models for best results:**

- [OpenAI GPT-5.4](https://openai.com/api/) - `openai/gpt-5.4`
- [Anthropic Claude Sonnet 4.6](https://claude.com/platform/api) - `anthropic/claude-sonnet-4-6`
- [Google Gemini 3 Pro Preview](https://cloud.google.com/vertex-ai) - `vertex_ai/gemini-3-pro-preview`

See the [LLM Providers documentation](https://docs.shadowstrike.dev/llm-providers/overview) for all supported providers including Vertex AI, Bedrock, Azure, and local models.

## Enterprise

Get the same Strix experience with [enterprise-grade](https://shadowstrike.dev/demo) controls: SSO (SAML/OIDC), custom compliance reports, dedicated support & SLA, custom deployment options (VPC/self-hosted), BYOK model support, and tailored agents optimized for your environment. [Learn more](https://shadowstrike.dev/demo).

## 📦 Features

ShadowStrike combines capabilities from [Strix](https://github.com/usestrix/strix), [strix-advanced](https://github.com/Hafiz380/strix-advanced), and concepts from [Shannon](https://github.com/KeygraphHQ/shannon):

### 🔬 Static Analysis Engine
- **CPG Builder** — tree-sitter based Code Property Graph (6 languages: Python, JS, TS, Go, Java, PHP)
- **Data Flow Analyzer** — Source → Sink taint tracing
- **Sanitizer Analyzer** — LLM-guided sanitizer effectiveness validation
- **20+ vulnerability types** with CWE/OWASP/CVSS mappings

### 🧠 Memory & Learning System
- **Scan Memory** — Per-scan SQLite storage
- **Global Memory** — Cross-scan knowledge accumulation
- **Dedup Engine** — Finding deduplication across scans
- **Skill Generator** — Auto-generate skills from scan experience

### 💥 Advanced Exploitation
- **Exploit Chain Builder** — Multi-vulnerability chaining (10 known patterns + novel discovery)
- **Auth Automator** — 2FA/TOTP/SSO/OAuth2/JWT handling
- **Race Condition Detector** — Concurrent request engine for TOCTOU bugs
- **Logic Fuzzer** — Business logic invariant testing
- **WAF Bypass** — 15+ evasion techniques for SQLi, XSS, SSRF, Path Traversal

### 🤖 Specialized Agents
- **Recon Agent** — Subdomain enum, DNS, tech fingerprinting, endpoint discovery
- **Exploit Agent** — SQLi, XSS, SSRF, RCE, SSTI, Path Traversal exploitation
- **Analysis Agent** — Static analysis integration
- **Report Agent** — Professional security reports with executive summary
- **Coordinator Agent** — Full scan orchestration pipeline

### 🔄 Parallel Pipeline (from Shannon)
- **5 Vuln Classes in Parallel** — Injection, XSS, Auth, Authorization, SSRF run concurrently
- **Vuln→Exploit Pairs** — Each class has sequential analysis→exploitation
- **Static-Dynamic Correlation** — Static findings fed to dynamic exploitation agents
- **Workspace System** — Checkpoint/resume interrupted scans (SQLite-backed)
- **Deliverable System** — Structured intermediate reports per pipeline phase

### 🧠 Learning & Memory (from everything-claude-code)
- **Instinct-Based Learning** — Auto-learn from scan sessions with confidence scoring (0.3–0.9)
- **Memory Persistence** — Cross-session context with bounded loading (prevents memory explosion)
- **Skill Evolution** — High-confidence instincts evolve into reusable skills
- **Project-Scoped Learning** — Separate project-specific and global instincts

### 🎯 Security Bounty Hunter
- **Bounty-Focused Scanning** — Only reports findings that bounty platforms accept
- **Skip Patterns** — Filters out local-only, CLI-only, and header-only issues
- **PoC Suggestions** — Each finding includes suggested exploit approach
- **Priority Ranking** — Critical/High/Medium/Low based on bounty-worthiness

### ✅ Verification Loop
- **5 Quality Gates** — Finding Validation, Exploit Verification, Dedup, Confidence, Report Quality
- **Auto-Dedup** — Fingerprint-based duplicate detection
- **Confidence Scoring** — Rates findings by evidence strength

### 📜 Multi-Language Security Rules (12+ Languages)
- **Python** — Django, FastAPI, Flask patterns
- **JavaScript/TypeScript** — React, Next.js, Express patterns
- **Java** — Spring Boot, JPA patterns
- **Go, PHP, Rust, Ruby** — Language-specific security patterns
- **Common Rules** — Secrets management, input validation, auth, error handling

### 📋 Additional Features
- **API Discovery** — Swagger/OpenAPI parsing, GraphQL introspection, brute-force, JS extraction
- **Supply Chain** — npm/pip/go/cargo dependency scanning, typosquat detection
- **Infrastructure** — DNS, SSL/TLS, security headers, CORS, cookies, cloud storage
- **Custom Rules** — 15+ built-in rules, YAML/JSON rule loading, directory scanning

### Usage (Advanced Commands)

```bash
# Install with advanced dependencies
pip install shadowstrike[advanced]

# Full security scan
strix-advanced scan https://target.com

# Code-only scan (white-box)
strix-advanced scan https://target.com --code ./src --type code

# Quick scan
strix-advanced scan https://target.com --type quick --depth quick

# Static analysis only
strix-advanced analyze ./src

# Reconnaissance only
strix-advanced recon https://target.com --depth deep

# Custom rules
strix-advanced rules list
strix-advanced rules scan ./code
strix-advanced rules export --output rules.yaml

# System info
strix-advanced info

# Parallel vulnerability pipeline (Shannon-inspired)
strix-advanced pipeline https://target.com
strix-advanced pipeline https://target.com --classes injection xss ssrf
strix-advanced pipeline https://target.com --code ./src --workspace my-audit
strix-advanced pipeline https://target.com --no-exploit

# Workspace management
strix-advanced workspace list
strix-advanced workspace resume my-audit
strix-advanced workspace delete my-audit

# Bounty-focused vulnerability scan
strix-advanced bounty ./src
strix-advanced bounty ./src --output bounty_report.md
```

### Vulnerability Types (Advanced)

| Vuln Type | CWE | OWASP |
|---|---|---|
| SQL Injection | CWE-89 | A03 |
| XSS | CWE-79 | A03 |
| RCE | CWE-78 | A03 |
| SSTI | CWE-1336 | A03 |
| SSRF | CWE-918 | A10 |
| Path Traversal | CWE-22 | A01 |
| IDOR | CWE-639 | A01 |
| CSRF | CWE-352 | A01 |
| XXE | CWE-611 | A05 |
| Deserialization | CWE-502 | A08 |
| Open Redirect | CWE-601 | - |
| NoSQL Injection | CWE-943 | A03 |
| Auth Bypass | CWE-287 | A07 |
| Race Condition | CWE-362 | A04 |

## Documentation

Full documentation is available at **[docs.shadowstrike.dev](https://docs.shadowstrike.dev)** - including detailed guides for usage, CI/CD integrations, skills, and advanced configuration.

## Contributing

We welcome contributions of code, docs, and new skills - check out our [Contributing Guide](https://docs.shadowstrike.dev/contributing) to get started or open a [pull request](https://github.com/Hafiz380/shadowstrike/pulls)/[issue](https://github.com/Hafiz380/shadowstrike/issues).

## Join Our Community

Have questions? Found a bug? Want to contribute? **[Join our Discord!](https://discord.gg/shadowstrike.dev)**

## Support the Project

**Love Strix?** Give us a ⭐ on GitHub!

## Acknowledgements

Strix builds on the incredible work of open-source projects like [LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido), [Nuclei](https://github.com/projectdiscovery/nuclei), [Playwright](https://github.com/microsoft/playwright), and [Textual](https://github.com/Textualize/textual). Huge thanks to their maintainers!


> [!WARNING]
> Only test apps you own or have permission to test. You are responsible for using Strix ethically and legally.

</div>
