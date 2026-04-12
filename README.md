# SolanaShield MCP

> AI-powered smart contract security for Solana programs via Model Context Protocol

**SolanaShield** is a specialized MCP server that brings 40+ Solana vulnerability patterns to any AI assistant. It detects critical security issues in Anchor/Solana programs including missing owner checks, arbitrary CPI, PDA confusion, integer overflow, reentrancy, and more.

Built for the [Colosseum Frontier Hackathon](https://www.colosseum.org/) (Apr 6 — May 11, 2026).

## Features

- **40 Vulnerability Patterns** — 8 Critical, 12 High, 12 Medium, 8 Low
- **12 MCP Tools** — Full audit, targeted checks, risk scoring, fix generation
- **Zero Dependencies** — Pure static analysis, no external APIs needed
- **Solana-Native** — Every pattern is specific to Solana/Anchor programs
- **JSON Output** — Machine-readable results for CI/CD integration

## Quick Start

```bash
npm install -g solanashield-mcp
```

Or clone and build:

```bash
git clone https://github.com/ElromEvedElElyon/solanashield-mcp.git
cd solanashield-mcp
npm install && npm run build
```

### Claude Desktop Configuration

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "solanashield": {
      "command": "node",
      "args": ["/path/to/solanashield-mcp/dist/index.js"]
    }
  }
}
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `audit-program` | Full security audit with severity-sorted findings |
| `check-accounts` | Account validation (owner, signer, authority) |
| `check-cpi` | Cross-Program Invocation safety analysis |
| `check-pda` | PDA seed confusion and bump storage checks |
| `check-arithmetic` | Integer overflow/underflow and precision loss |
| `check-tokens` | SPL Token authority, mint, and freeze checks |
| `risk-score` | Quick 0-100 risk score for triage |
| `list-patterns` | Browse all vulnerability patterns |
| `explain-finding` | Detailed exploit scenarios and remediation |
| `generate-fix` | Auto-generate code fixes for findings |
| `compare-versions` | Diff two code versions for regression analysis |
| `audit-json` | Structured JSON output for programmatic use |

## Vulnerability Categories

| Category | Patterns | Example |
|----------|----------|---------|
| Access Control | 3 | Missing owner check, missing signer |
| CPI Safety | 4 | Arbitrary CPI, reentrancy, privilege escalation |
| PDA Safety | 2 | Seed confusion, bump not stored |
| Token Safety | 4 | Authority mismatch, mint/freeze authority |
| Arithmetic | 2 | Integer overflow, precision loss |
| State Safety | 5 | Reinitialization, account close, rent exemption |
| DeFi | 1 | Flash loan via CPI |
| Oracle Safety | 1 | Stale price feed |
| Deserialization | 2 | Type cosplay, unsafe deserialization |
| Anchor | 2 | Missing constraints, init_if_needed |
| DoS | 1 | Unbounded iteration |
| Logic | 1 | Timestamp dependence |
| Observability | 2 | Missing events, missing logging |
| Optimization | 2 | Unused accounts, CU optimization |
| Code Quality | 3 | Magic numbers, test code, missing docs |
| Configuration | 1 | Hardcoded addresses |
| Error Handling | 1 | Missing error context |
| Maintenance | 1 | Deprecated API usage |

## Example Output

```
Risk Score: 62/100 (HIGH)
Critical: 1 | High: 3 | Medium: 1 | Low: 3
Total findings: 8 across 19 lines

RECOMMENDATION: Do NOT deploy without fixing critical and high findings.
```

## Architecture

```
src/
  index.ts              # MCP server with 12 tool registrations
  patterns/
    solana-patterns.ts  # 40 vulnerability pattern definitions
  analyzers/
    static-analyzer.ts  # Pattern matching engine + report formatting
```

## Colosseum Frontier Hackathon

SolanaShield is competing in the [Solana Frontier Hackathon](https://colosseum.com/frontier) (Apr 6 — May 11, 2026):

- **$30K** Grand Champion + **$250K** pre-seed funding
- **Category**: Security / Developer Tools
- **Status**: Registered and building

### Why SolanaShield?

Every Solana program deployed without a security audit is a potential exploit waiting to happen. SolanaShield makes security accessible to every developer by integrating directly into their AI workflow via MCP. No expensive audit firms, no waiting weeks — instant security analysis.

### Roadmap

- [x] 40 vulnerability patterns (8 critical, 12 high)
- [x] 12 MCP tools
- [x] Published on npm (`solanashield-mcp`)
- [x] x402 pay-per-audit server
- [ ] Real-time monitoring (watch deployed programs)
- [ ] Anchor IDL parsing
- [ ] Multi-program analysis (CPI chains)
- [ ] VS Code extension
- [ ] CI/CD GitHub Action

## License

MIT

## Author

**PadraoBitcoin** — [standardbitcoin.io@gmail.com](mailto:standardbitcoin.io@gmail.com)
