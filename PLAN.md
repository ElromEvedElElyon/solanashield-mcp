# SolanaShield — AI-Powered Smart Contract Security MCP Server for Solana
## Colosseum Frontier Hackathon Project Plan
### Em nome do Senhor Jesus Cristo, nosso Salvador.

---

## Project Identity

- **Name**: SolanaShield
- **Tagline**: "AI-powered security analysis for Solana programs, exposed as an MCP server"
- **Track**: Infrastructure
- **Hackathon**: Colosseum Frontier (Apr 6 - May 11, 2026, $2.5M prize pool)
- **Team**: PadraoBitcoin (standardbitcoin.io@gmail.com)
- **Account**: Colosseum — PadraoBitcoin, registered

---

## Problem Statement

Solana smart contract (program) security is fundamentally different from EVM security. Existing tools are EVM-centric. Developers building on Solana face:

1. **No MCP-based security tools** — Claude Code, Cursor, and other AI IDEs cannot natively audit Solana programs
2. **Unique Solana attack surface** — account validation, CPI safety, PDA derivation, rent exemption, and Anchor-specific patterns are NOT covered by EVM auditors
3. **High cost of audits** — manual audits cost $50K-$200K; automated tools are incomplete
4. **Developer friction** — security checks are disconnected from the development workflow

---

## Solution

SolanaShield is an MCP (Model Context Protocol) server that exposes Solana-specific security analysis tools directly inside AI-powered IDEs (Claude Code, Cursor, Windsurf, etc.). Developers get instant security feedback as they code, with no context switching.

### How It Works

```
Developer writes Solana/Anchor code
        |
        v
Claude Code / Cursor calls SolanaShield MCP tools
        |
        v
SolanaShield runs 4-pass analysis:
  Pass 1: Static pattern matching (40+ Solana-specific patterns, instant)
  Pass 2: Anchor IDL analysis (account constraint verification)
  Pass 3: CPI call graph tracing (cross-program invocation safety)
  Pass 4: AI-powered deep audit (using Gemini/Claude for complex logic)
        |
        v
Results returned as structured findings with severity, PoC, and fix
```

---

## Architecture Overview

```
colosseum-solanashield/
|-- package.json                  # Node.js MCP server package
|-- tsconfig.json                 # TypeScript config
|-- src/
|   |-- index.ts                  # MCP server entry point (stdio JSON-RPC 2.0)
|   |-- server.ts                 # Server setup, tool registration
|   |-- tools/
|   |   |-- audit-program.ts      # Full 4-pass Solana program audit
|   |   |-- check-accounts.ts     # Account validation checker
|   |   |-- check-cpi.ts          # CPI safety analyzer
|   |   |-- check-pda.ts          # PDA derivation verifier
|   |   |-- check-math.ts         # Integer overflow/underflow detection
|   |   |-- check-signer.ts       # Missing signer check detection
|   |   |-- check-rent.ts         # Rent exemption verification
|   |   |-- check-anchor.ts       # Anchor-specific pattern checker
|   |   |-- check-reentrancy.ts   # CPI reentrancy detector
|   |   |-- generate-poc.ts       # PoC exploit generator
|   |   |-- explain-finding.ts    # AI-powered finding explainer
|   |-- patterns/
|   |   |-- solana-patterns.ts    # 40+ Solana vulnerability patterns (regex + keywords)
|   |   |-- anchor-patterns.ts    # Anchor framework-specific patterns
|   |   |-- evm-patterns.ts       # Reused from israel-four VULN_DB (30 EVM patterns)
|   |-- analyzers/
|   |   |-- static-analyzer.ts    # Pattern matching engine (port of CyberSentinel Pass 1)
|   |   |-- anchor-analyzer.ts    # Anchor IDL parser and constraint checker
|   |   |-- cpi-tracer.ts         # Cross-program invocation graph builder
|   |   |-- ai-auditor.ts         # AI-powered deep analysis (Gemini 2.5 free API)
|   |-- types/
|   |   |-- findings.ts           # Finding, Severity, Report type definitions
|   |   |-- solana.ts             # Solana-specific type definitions
|   |-- utils/
|   |   |-- parser.ts             # Rust/Anchor code parser utilities
|   |   |-- reporter.ts           # Report formatter (JSON, Markdown)
|-- tests/
|   |-- test-programs/            # Vulnerable Solana programs for testing
|   |   |-- missing-signer.rs
|   |   |-- unsafe-cpi.rs
|   |   |-- pda-confusion.rs
|   |   |-- overflow-unchecked.rs
|   |   |-- reentrancy-cpi.rs
|   |-- audit.test.ts
|   |-- patterns.test.ts
|-- web/                          # Demo frontend (adapted from contractscan-ai)
|   |-- index.html                # Static page for hackathon demo
|   |-- app.js                    # Frontend logic
|-- README.md
|-- LICENSE                       # MIT
```

---

## MCP Tools List (Security Checks Exposed)

### Core Audit Tool

| # | Tool Name | Description | Input | Output |
|---|-----------|-------------|-------|--------|
| 1 | `solana_audit` | Full 4-pass security audit of a Solana/Anchor program | `code: string`, `framework?: "anchor"\|"native"` | Structured findings with severity, line numbers, PoC, fix |

### Targeted Check Tools

| # | Tool Name | Description | Solana-Specific? |
|---|-----------|-------------|------------------|
| 2 | `check_accounts` | Verify account validation (owner checks, signer checks, PDA seeds) | YES |
| 3 | `check_cpi` | Analyze CPI calls for program ID verification and privilege escalation | YES |
| 4 | `check_pda` | Verify PDA derivation correctness and seed collision risks | YES |
| 5 | `check_math` | Detect integer overflow/underflow in unchecked arithmetic | Partial (Rust-specific) |
| 6 | `check_signer` | Find missing signer checks on state-changing instructions | YES |
| 7 | `check_rent` | Verify rent exemption handling and account closure safety | YES |
| 8 | `check_anchor` | Anchor-specific checks (constraint validation, account deserialization) | YES |
| 9 | `check_reentrancy` | Detect CPI reentrancy vectors (unique to Solana's CPI model) | YES |

### Utility Tools

| # | Tool Name | Description |
|---|-----------|-------------|
| 10 | `generate_poc` | Generate a Solana test PoC (TypeScript/Rust) for a finding |
| 11 | `explain_finding` | AI-powered plain-language explanation of a vulnerability |
| 12 | `list_patterns` | List all 40+ vulnerability patterns in the database |

---

## Solana-Specific Vulnerability Patterns (40+)

### CRITICAL (8 patterns)

| ID | Name | Description |
|----|------|-------------|
| SOL-001 | Missing Owner Check | Program does not verify account owner matches expected program |
| SOL-002 | Missing Signer Check | State-changing instruction does not require signer |
| SOL-003 | Arbitrary CPI | Cross-program invocation without verifying target program ID |
| SOL-004 | PDA Seed Confusion | PDA derived with user-controlled seeds allowing account substitution |
| SOL-005 | Account Reinitialization | Account can be initialized multiple times (missing `is_initialized` check) |
| SOL-006 | Closing Account Vulnerability | Account closed but lamports/data not zeroed, allowing revival |
| SOL-007 | Type Cosplay | Account deserialized as wrong type (missing discriminator check) |
| SOL-008 | Privilege Escalation via CPI | CPI signer seeds allow unauthorized privilege escalation |

### HIGH (12 patterns)

| ID | Name | Description |
|----|------|-------------|
| SOL-010 | Integer Overflow (unchecked) | Arithmetic in `unchecked {}` or raw operations without overflow protection |
| SOL-011 | CPI Reentrancy | State read before CPI, then used after — stale state attack |
| SOL-012 | Missing Rent Exemption Check | Account may fall below rent-exempt minimum, causing garbage collection |
| SOL-013 | Duplicate Mutable Accounts | Same account passed as two different mutable parameters |
| SOL-014 | Token Account Authority Mismatch | SPL Token account authority not validated against expected key |
| SOL-015 | Mint Authority Not Checked | Token mint authority not verified, allowing unauthorized minting |
| SOL-016 | Oracle Stale Price (Pyth/Switchboard) | Price oracle data age not validated against staleness threshold |
| SOL-017 | Missing Program ID Check in CPI | `invoke` or `invoke_signed` without validating callee program ID |
| SOL-018 | Account Data Matching | Account data used without verifying it matches expected schema |
| SOL-019 | Unsafe Deserialization | `try_from_slice` or `borsh::deserialize` without length/bounds check |
| SOL-020 | Flash Loan via CPI | CPI callback pattern allowing atomic borrow-manipulate-repay |
| SOL-021 | Lamport Transfer Vulnerability | Direct lamport manipulation bypassing token program safety |

### MEDIUM (12 patterns)

| ID | Name | Description |
|----|------|-------------|
| SOL-030 | Missing Anchor Constraint | `#[account]` without `has_one`, `constraint`, or `seeds` validation |
| SOL-031 | PDA Bump Seed Not Stored | Bump seed not stored/verified, allowing off-curve key attacks |
| SOL-032 | Unchecked Remaining Accounts | `ctx.remaining_accounts` used without validation |
| SOL-033 | Missing Token Program Check | SPL Token program ID not verified (could be fake token program) |
| SOL-034 | Unsafe Account Close | Account closed without zeroing data (data remains readable) |
| SOL-035 | Cross-Instruction State Leak | State modified in one instruction visible to next in same tx |
| SOL-036 | Precision Loss in Token Math | Division before multiplication in token amount calculations |
| SOL-037 | Missing System Program Check | System program not verified in account creation |
| SOL-038 | Unnecessary Mutability | Account marked `mut` when only read, increasing attack surface |
| SOL-039 | Missing Freeze Authority Check | Token account freeze authority not validated |
| SOL-040 | Unsafe Seed Generation | PDA seeds derived from untrusted input without sanitization |
| SOL-041 | Account Size Mismatch | Account allocation size does not match serialized data size |

### LOW (8 patterns)

| ID | Name | Description |
|----|------|-------------|
| SOL-050 | Missing Error Handling | `.unwrap()` without `.ok_or(ErrorCode)` in program logic |
| SOL-051 | Unused Account in Instruction | Account declared in context but never accessed |
| SOL-052 | Missing Logging | State changes without `msg!()` or event emission |
| SOL-053 | Magic Numbers | Hardcoded numeric values instead of named constants |
| SOL-054 | Gas/CU Optimization | Unnecessary compute unit consumption (extra clones, allocations) |
| SOL-055 | Missing Documentation | Public instruction without doc comments |
| SOL-056 | Deprecated API Usage | Using deprecated Solana SDK functions |
| SOL-057 | Test-Only Code in Production | `#[cfg(test)]`-gated code leaking into production paths |

---

## Existing Code to Reuse

### From ~/israel-four/ (Primary Source)

| Component | File | What to Reuse | Adaptation Needed |
|-----------|------|---------------|-------------------|
| MCP server protocol | `mcp/mythos_mcp_server.py` | Full JSON-RPC 2.0 stdio implementation (initialize, tools/list, tools/call) | Port from Python to TypeScript |
| Static audit engine | `israel_four_mega.py` (Hands.static_audit) | Pattern matching engine: iterate VULN_DB, regex match per line, collect findings | Port to TypeScript, replace EVM patterns with Solana patterns |
| Vulnerability database | `israel_four_mega.py` (VULN_DB, 30 patterns) | Pattern structure: `{id, name, severity, regex, check}` | Keep structure, add Solana-specific patterns (40+ new) |
| CyberSentinel patterns | `mythic_engine.py` (VULN_PATTERNS, 60 patterns) | Extended pattern structure with CVSS scores, keywords, descriptions | Keep EVM patterns as reference, create parallel Solana set |
| AI audit methodology | `mythic_engine.py` (CyberSentinel.SYSTEM_PROMPT) | 4-pass audit methodology (Read, Check, Trace, Economic) | Adapt system prompt for Solana/Anchor context |
| Deep audit pipeline | `israel_four_mega.py` (Hands.deep_audit) | Static + AI dual-pass approach, report generation | Port pipeline, replace OpenAI calls with Gemini 2.5 free API |
| Exploit generator | `israel_four_mega.py` (Hands.generate_exploit) | PoC generation prompt template | Adapt for Solana TypeScript tests instead of Foundry |
| Test contract | `test_contracts/vulnerable_vault.sol` | Example of intentionally vulnerable code for testing | Create equivalent Solana/Anchor test programs |
| MCP tool definitions | `mcp/capybara_tools.json` | Tool schema structure (inputSchema, required fields) | Expand for 12 Solana-specific tools |

### From ~/contractscan-ai/ (Demo Frontend)

| Component | File | What to Reuse | Adaptation Needed |
|-----------|------|---------------|-------------------|
| Frontend UI | `src/app/page.tsx` | Drop-zone file upload, result display cards, risk-level badges, gradient design | Replace "contract analysis" with "Solana program audit", add code editor |
| API route | `src/app/api/analyze/route.ts` | FormData handling, AI call pattern, JSON response parsing | Replace OpenAI with Gemini, change system prompt for Solana |
| Design system | `src/app/globals.css` | Tailwind dark theme, glass-morphism cards | Reuse as-is, change purple to green (Solana brand) |
| Package setup | `package.json` | Next.js + React + Tailwind + TypeScript scaffold | Fork and modify for SolanaShield branding |

### From ~/capybara-ai/mythic_engine.py (Audit Engine)

| Component | What to Reuse |
|-----------|---------------|
| ModelRouter | Multi-model routing (Gemini primary, OpenRouter fallback) — keeps costs at $0 |
| CyberSentinel 4-pass methodology | Read > Check > Trace > Economic analysis framework |
| 60 VULN_PATTERNS with CVSS | Full pattern structure with id, name, severity, cvss, keywords, regex, desc |
| Report formatting | Structured output with severity counts, cost tracking, timestamps |

---

## Technology Stack

| Layer | Technology | Reason |
|-------|-----------|--------|
| MCP Server | TypeScript + Node.js | Industry standard for MCP servers (Claude Code ecosystem) |
| Protocol | JSON-RPC 2.0 over stdio | MCP specification requirement |
| Static Analysis | Regex + AST parsing | Fast, offline, no API cost |
| AI Analysis | Google Gemini 2.5 Flash (free) | Zero cost, good quality, fast |
| AI Fallback | OpenRouter free models | Backup when Gemini is rate-limited |
| Demo Frontend | Next.js + Tailwind | Reuse contractscan-ai scaffold |
| Solana Parsing | Custom Rust/Anchor parser | Understand account contexts, CPI calls, PDA derivations |
| Testing | Vitest | Fast TypeScript test runner |
| Distribution | npm | Standard MCP server distribution channel |

### API Keys (Already Available, Zero Cost)

- **Gemini 2.5 Flash**: `AIzaSyBoiVhqZyt53C0hY8pcpnWncUB6y9kFL7I` (free unlimited)
- **OpenRouter**: `sk-or-v1-0738ea...` (25 free models)
- **Cerebras**: `csk-f2kt...` (1M tok/day free)

---

## 2-Week Build Timeline

### Week 1: Core Engine (Apr 6-12)

| Day | Date | Deliverable | Hours |
|-----|------|-------------|-------|
| 1 | Apr 6 | Project scaffold: package.json, tsconfig, MCP server boilerplate (port from mythos_mcp_server.py) | 6h |
| 2 | Apr 7 | Solana vulnerability pattern database (40+ patterns in TypeScript) | 6h |
| 3 | Apr 8 | Static analysis engine (port CyberSentinel Pass 1 to TypeScript) | 6h |
| 4 | Apr 9 | Account validation checker (check_accounts, check_signer, check_pda) | 6h |
| 5 | Apr 10 | CPI safety analyzer (check_cpi, check_reentrancy) | 6h |
| 6 | Apr 11 | Anchor-specific checker (check_anchor, IDL parsing) | 6h |
| 7 | Apr 12 | AI-powered deep audit integration (Gemini 2.5, 4-pass prompt) | 6h |

### Week 2: Polish + Demo (Apr 13-19)

| Day | Date | Deliverable | Hours |
|-----|------|-------------|-------|
| 8 | Apr 13 | PoC generator + finding explainer tools | 4h |
| 9 | Apr 14 | Test suite: 5 vulnerable Solana programs + audit correctness tests | 6h |
| 10 | Apr 15 | Demo frontend (fork contractscan-ai, Solana branding) | 4h |
| 11 | Apr 16 | npm publish + Claude Code integration testing | 4h |
| 12 | Apr 17 | README, documentation, architecture diagram | 3h |
| 13 | Apr 18 | Demo video recording (3 min) | 3h |
| 14 | Apr 19 | Final polish, submission | 2h |

**Total estimated: ~68 hours over 14 days**

### Buffer: Apr 20 - May 11 (22 days)

- Community feedback incorporation
- Additional patterns from real Solana audits
- Performance optimization
- Integration with Colosseum Copilot MCP (requires PAT token from arena.colosseum.org/copilot)

---

## Demo Strategy (3-Minute Video)

### Script (180 seconds)

**[0:00-0:20] Hook** (20s)
- "Solana developers lose millions to preventable vulnerabilities every year."
- Show headline: "Wormhole $320M hack", "Mango Markets $114M exploit"
- "What if your IDE could catch these before deployment?"

**[0:20-0:50] Problem** (30s)
- Show a Solana program with a missing signer check
- "This looks fine... but it has a critical vulnerability."
- "Existing tools? They are built for Ethereum. They miss Solana-specific issues."

**[0:50-1:30] Solution Demo** (40s)
- Open Claude Code with SolanaShield installed
- Type: "Audit this Solana program for security issues"
- SolanaShield returns: finding SOL-002 (Missing Signer Check), CRITICAL, with line number, explanation, and fix
- Show the structured output: severity badge, PoC code, recommended fix

**[1:30-2:10] Feature Walkthrough** (40s)
- Quick demo of individual tools:
  - `check_accounts` on a program with missing owner validation
  - `check_cpi` on a program with unverified CPI target
  - `generate_poc` producing a TypeScript test that exploits the finding
- Show pattern count: "40+ Solana-specific vulnerability patterns"

**[2:10-2:40] Technical Depth** (30s)
- Architecture diagram: MCP server, 4-pass analysis, AI integration
- "Static analysis is instant and free. AI pass uses Gemini 2.5 for deep logic analysis."
- "Works with Claude Code, Cursor, Windsurf, and any MCP-compatible IDE."

**[2:40-3:00] Close** (20s)
- "SolanaShield. Security that lives where you code."
- Show npm install command: `npx solanashield`
- GitHub link, MIT license
- "Built for Solana. Built for developers. Built at Colosseum Frontier."

---

## Competitive Advantage

| Feature | SolanaShield | Existing Tools |
|---------|-------------|----------------|
| MCP native | YES (first Solana security MCP) | NO |
| Solana-specific patterns | 40+ dedicated | 0-5 (EVM-focused) |
| IDE integration | Claude Code, Cursor, Windsurf | Standalone CLI only |
| AI-powered deep audit | Gemini 2.5 (free, instant) | Paid or none |
| Cost | FREE (open source) | $50K-$200K for manual audits |
| Anchor awareness | Full IDL + constraint checking | None |
| CPI tracing | Cross-program call graph analysis | None |
| PoC generation | Automated TypeScript test generation | Manual only |

---

## Colosseum Copilot MCP Integration

The Colosseum Copilot MCP (`github:securecheckio/colosseum-copilot-mcp`) is available and installable:

```bash
npx github:securecheckio/colosseum-copilot-mcp --help
# Requires: COLOSSEUM_COPILOT_PAT environment variable
# Token from: https://arena.colosseum.org/copilot
```

**Action Required**: Generate PAT token at arena.colosseum.org/copilot to enable:
- Project registration via MCP
- Submission automation
- Hackathon-specific tooling

**Integration Plan**: SolanaShield can optionally use Colosseum Copilot MCP alongside its own tools, providing both hackathon workflow management and security analysis in one IDE session.

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| OOM crashes (3.3GB RAM) | TypeScript is lighter than Python; static analysis is memory-efficient; AI calls are streamed |
| Gemini rate limits | Fallback to OpenRouter free models (Cerebras, Qwen) |
| npm publish token expired | Use `npx` distribution (no npm account needed for users) |
| Anchor version changes | Pattern database versioned; support Anchor 0.29+ |
| Time pressure | Core engine (Week 1) is MVP; Week 2 is polish; 22-day buffer exists |

---

## Success Metrics

- [ ] 12 MCP tools functional and tested
- [ ] 40+ Solana vulnerability patterns with zero false negatives on test programs
- [ ] Under 2 seconds for static analysis pass
- [ ] Demo video under 3 minutes
- [ ] Published to npm as `solanashield`
- [ ] GitHub Pages demo site live
- [ ] Submitted to Colosseum before May 11 deadline

---

## Revenue Potential Post-Hackathon

- **Freemium MCP server**: Free static analysis, paid AI-powered deep audit ($9.99/mo)
- **Enterprise**: Custom pattern libraries for Solana protocols ($99/mo)
- **Bug bounty amplifier**: Use SolanaShield to find real vulnerabilities, submit to Immunefi/C4
- **Audit marketplace**: Connect auditors with projects needing security review

---

*Em nome do Senhor Jesus Cristo. Ship daily. Security is sovereignty.*
