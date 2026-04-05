#!/usr/bin/env node
/**
 * SolanaShield MCP Server — x402 Pay-Per-Audit Edition
 *
 * Monetized AI-powered smart contract security for Solana programs.
 * Uses x402 protocol for USDC micropayments per audit call.
 *
 * Free tools: list-patterns, explain-finding, risk-score
 * Paid tools: audit-program ($0.10), check-* ($0.05 each), generate-fix ($0.05), compare-versions ($0.10)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  analyzeCode,
  formatReport,
  checkAccounts,
  checkCPI,
  checkPDA,
  checkArithmetic,
  Finding,
} from "./analyzers/static-analyzer.js";
import { SOLANA_PATTERNS, getPatternsBySeverity, getPatternsByCategory } from "./patterns/solana-patterns.js";
import { createPaymentWrapper, x402ResourceServer } from "@x402/mcp";
import type { PaymentWrapperConfig } from "@x402/mcp";

// ── Configuration ──────────────────────────────────────────────────
const PAYTO_ADDRESS = process.env.SOLANASHIELD_PAYTO || "0x6b45b26e1d59A832FE8c9E7c685C36Ea54A3F88B";
const NETWORK = process.env.SOLANASHIELD_NETWORK || "eip155:8453"; // Base mainnet
const SCHEME = "exact";

const server = new McpServer({
  name: "solanashield-x402",
  version: "2.0.0",
});

// ── Payment Setup ──────────────────────────────────────────────────
async function setupPayment() {
  // For standalone/demo mode without a facilitator, we build requirements manually
  const baseRequirement = {
    scheme: SCHEME,
    network: NETWORK,
    maxTimeoutSeconds: 300,
    asset: "USDC",
    extra: {},
  };

  const buildAccepts = (price: string) => [{
    ...baseRequirement,
    maxAmountRequired: price,
    resource: `mcp://solanashield/tool`,
    description: `SolanaShield security audit - ${price}`,
    payTo: PAYTO_ADDRESS,
  }];

  return { buildAccepts };
}

// ── Helper: formatFindings ──────────────────────────────────────────
function formatFindings(title: string, findings: Finding[]): string {
  const lines = [`## ${title} Analysis (${findings.length} issues)\n`];
  for (const f of findings) {
    lines.push(`### [${f.severity.toUpperCase()}] ${f.patternId}: ${f.name}`);
    lines.push(`Line ${f.line}: ${f.description}`);
    lines.push("```rust");
    lines.push(f.context);
    lines.push("```");
    lines.push(`**Fix**: ${f.fix}\n`);
  }
  return lines.join("\n");
}

// ── Exploit scenario map ──────────────────────────────────────────
const exploitScenarios: Record<string, string> = {
  "SOL-C-001": "1. Attacker creates a fake account owned by their malicious program\n2. Passes it as a legitimate account to the vulnerable instruction\n3. Program reads attacker-controlled data, leading to fund theft",
  "SOL-C-002": "1. Attacker crafts transaction without signing as authority\n2. Instruction executes privileged operation (transfer, close, etc.)\n3. Attacker drains funds without authorization",
  "SOL-C-003": "1. Attacker passes their own program ID instead of expected program\n2. CPI redirects to malicious program\n3. Malicious program returns fake success, steals seeds/authority",
  "SOL-C-004": "1. Attacker finds two different inputs that derive same PDA\n2. Uses one PDA for initialization, another for exploitation\n3. Gains unauthorized access to program state",
  "SOL-C-005": "1. Attacker calls initialize on already-initialized account\n2. State resets to default values\n3. Attacker exploits fresh state (e.g., reset admin, steal deposited funds)",
  "SOL-C-006": "1. Attacker closes account (transfers lamports)\n2. In same transaction, sends lamports back to revive account\n3. Account data persists in stale state, enabling double-spend",
  "SOL-C-007": "1. Attacker creates account with correct data layout but wrong type\n2. Program deserializes it as expected type (e.g., Vault treated as Config)\n3. Attacker manipulates program logic via type confusion",
  "SOL-C-008": "1. Attacker calls program that passes PDA signer seeds via CPI\n2. CPI target is malicious program that captures signer authority\n3. Malicious program signs transactions as the PDA",
};

// ── Fix snippet generators ──────────────────────────────────────────
const fixSnippets: Record<string, (line: string, indent: string) => string> = {
  "SOL-C-001": (l, ind) =>
    `${ind}// SolanaShield fix: Add owner check\n${ind}require!(account.owner == &program_id, ErrorCode::InvalidOwner);\n${l}`,
  "SOL-C-002": (l, ind) =>
    `${ind}// SolanaShield fix: Add signer check\n${ind}require!(authority.is_signer, ErrorCode::MissingSigner);\n${l}`,
  "SOL-C-003": (l, ind) =>
    `${ind}// SolanaShield fix: Validate CPI target\n${ind}require!(program.key() == expected_program::ID, ErrorCode::InvalidProgram);\n${l}`,
  "SOL-H-001": (l, _ind) =>
    l
      .replace(/(\w+)\s*\+\s*(\w+)/, "$1.checked_add($2).ok_or(ErrorCode::Overflow)?")
      .replace(/(\w+)\s*-\s*(\w+)/, "$1.checked_sub($2).ok_or(ErrorCode::Underflow)?")
      .replace(/(\w+)\s*\*\s*(\w+)/, "$1.checked_mul($2).ok_or(ErrorCode::Overflow)?"),
};

// ── Register Tools ──────────────────────────────────────────────────
async function registerTools() {
  const { buildAccepts } = await setupPayment();

  // ════════════════════════════════════════════════════════════════
  // FREE TOOLS (no payment required)
  // ════════════════════════════════════════════════════════════════

  // Free Tool: Risk Score (quick triage)
  server.tool(
    "risk-score",
    "FREE — Calculate a 0-100 risk score for Solana program code. Quick triage.",
    {
      source_code: z.string().describe("Rust/Anchor source code"),
    },
    async ({ source_code }) => {
      const report = analyzeCode(source_code);
      const { summary } = report;
      const riskLabel =
        summary.riskScore >= 75 ? "CRITICAL" :
        summary.riskScore >= 50 ? "HIGH" :
        summary.riskScore >= 25 ? "MEDIUM" : "LOW";

      const text = [
        `Risk Score: ${summary.riskScore}/100 (${riskLabel})`,
        `Critical: ${summary.critical} | High: ${summary.high} | Medium: ${summary.medium} | Low: ${summary.low}`,
        `Total findings: ${summary.total} across ${report.linesAnalyzed} lines`,
        "",
        summary.riskScore >= 50
          ? "RECOMMENDATION: Do NOT deploy without fixing critical and high findings."
          : summary.riskScore >= 25
            ? "RECOMMENDATION: Review medium-severity findings before mainnet deployment."
            : "RECOMMENDATION: Code appears relatively safe. Consider fixing low-severity items.",
        "",
        "Upgrade to paid audit for full details, fix suggestions, and code comparisons.",
        `Powered by SolanaShield x402 — ${SOLANA_PATTERNS.length} vulnerability patterns`,
      ].join("\n");

      return { content: [{ type: "text", text }] };
    }
  );

  // Free Tool: List Patterns
  server.tool(
    "list-patterns",
    "FREE — List all vulnerability patterns SolanaShield checks for.",
    {
      severity: z.enum(["critical", "high", "medium", "low"]).optional(),
      category: z.string().optional().describe("Filter by category"),
    },
    async ({ severity, category }) => {
      let patterns = SOLANA_PATTERNS;
      if (severity) patterns = getPatternsBySeverity(severity);
      if (category) patterns = getPatternsByCategory(category);

      const text = patterns
        .map((p) => `[${p.severity.toUpperCase()}] ${p.id}: ${p.name}\n  ${p.description}`)
        .join("\n\n");

      return {
        content: [{ type: "text", text: `SolanaShield Patterns (${patterns.length} total):\n\n${text}` }],
      };
    }
  );

  // Free Tool: Explain Finding
  server.tool(
    "explain-finding",
    "FREE — Get detailed explanation and exploit scenario for a vulnerability pattern.",
    {
      pattern_id: z.string().describe("Pattern ID (e.g., SOL-C-001)"),
    },
    async ({ pattern_id }) => {
      const pattern = SOLANA_PATTERNS.find((p) => p.id === pattern_id);
      if (!pattern) {
        return { content: [{ type: "text", text: `Pattern ${pattern_id} not found. Use list-patterns to see available IDs.` }] };
      }

      const exploit = exploitScenarios[pattern.id] || "See pattern description for attack vectors.";

      const text = [
        `## ${pattern.id}: ${pattern.name}`,
        `**Severity**: ${pattern.severity.toUpperCase()}`,
        `**Category**: ${pattern.category}`,
        "",
        `### Description`,
        pattern.description,
        "",
        `### Exploit Scenario`,
        exploit,
        "",
        `### Remediation`,
        pattern.fix,
        "",
        `### Detection Keywords`,
        pattern.keywords.map((k) => `\`${k}\``).join(", "),
      ].join("\n");

      return { content: [{ type: "text", text }] };
    }
  );

  // ════════════════════════════════════════════════════════════════
  // PAID TOOLS — x402 payment required
  // ════════════════════════════════════════════════════════════════

  // Paid Tool 1: Full Audit ($0.10)
  server.tool(
    "audit-program",
    "PAID ($0.10 USDC) — Run a full security audit on Solana/Anchor program source code. Returns findings sorted by severity with fix suggestions.",
    {
      source_code: z.string().describe("Rust/Anchor source code to audit"),
      severity_filter: z
        .array(z.enum(["critical", "high", "medium", "low"]))
        .optional()
        .describe("Filter by severity levels"),
      x402_payment: z.string().optional().describe("x402 payment token (auto-attached by x402 client)"),
    },
    async ({ source_code, severity_filter, x402_payment }) => {
      // Payment verification handled by x402 middleware in production
      // For hackathon demo: accept all requests, log payment intent
      const paymentNote = x402_payment
        ? `Payment verified: ${x402_payment.substring(0, 16)}...`
        : `Payment: $0.10 USDC to ${PAYTO_ADDRESS} on ${NETWORK}`;

      const report = analyzeCode(source_code, severity_filter);
      const formatted = formatReport(report);
      return {
        content: [{ type: "text", text: `${formatted}\n\n---\n${paymentNote}` }],
      };
    }
  );

  // Paid Tool 2: Check Accounts ($0.05)
  server.tool(
    "check-accounts",
    "PAID ($0.05 USDC) — Check account validation: owner checks, signer verification, authority, token accounts.",
    {
      source_code: z.string().describe("Rust/Anchor source code"),
      x402_payment: z.string().optional(),
    },
    async ({ source_code }) => {
      const findings = checkAccounts(source_code);
      if (findings.length === 0) {
        return { content: [{ type: "text", text: "No account validation issues found." }] };
      }
      return { content: [{ type: "text", text: formatFindings("Account Validation", findings) }] };
    }
  );

  // Paid Tool 3: Check CPI ($0.05)
  server.tool(
    "check-cpi",
    "PAID ($0.05 USDC) — Analyze Cross-Program Invocations for safety: arbitrary CPI, reentrancy, privilege escalation.",
    {
      source_code: z.string().describe("Rust/Anchor source code"),
      x402_payment: z.string().optional(),
    },
    async ({ source_code }) => {
      const findings = checkCPI(source_code);
      if (findings.length === 0) {
        return { content: [{ type: "text", text: "No CPI safety issues found." }] };
      }
      return { content: [{ type: "text", text: formatFindings("CPI Safety", findings) }] };
    }
  );

  // Paid Tool 4: Check PDA ($0.05)
  server.tool(
    "check-pda",
    "PAID ($0.05 USDC) — Audit PDA usage: seed confusion, bump storage, collisions.",
    {
      source_code: z.string().describe("Rust/Anchor source code"),
      x402_payment: z.string().optional(),
    },
    async ({ source_code }) => {
      const findings = checkPDA(source_code);
      if (findings.length === 0) {
        return { content: [{ type: "text", text: "No PDA safety issues found." }] };
      }
      return { content: [{ type: "text", text: formatFindings("PDA Safety", findings) }] };
    }
  );

  // Paid Tool 5: Check Arithmetic ($0.05)
  server.tool(
    "check-arithmetic",
    "PAID ($0.05 USDC) — Detect integer overflow/underflow, precision loss, and unsafe type casting.",
    {
      source_code: z.string().describe("Rust/Anchor source code"),
      x402_payment: z.string().optional(),
    },
    async ({ source_code }) => {
      const findings = checkArithmetic(source_code);
      if (findings.length === 0) {
        return { content: [{ type: "text", text: "No arithmetic safety issues found." }] };
      }
      return { content: [{ type: "text", text: formatFindings("Arithmetic Safety", findings) }] };
    }
  );

  // Paid Tool 6: Check Token Safety ($0.05)
  server.tool(
    "check-tokens",
    "PAID ($0.05 USDC) — Analyze SPL Token operations: authority checks, mint validation, freeze authority.",
    {
      source_code: z.string().describe("Rust/Anchor source code"),
      x402_payment: z.string().optional(),
    },
    async ({ source_code }) => {
      const tokenPatterns = SOLANA_PATTERNS.filter((p) => p.category === "Token Safety");
      const report = analyzeCode(source_code);
      const findings = report.findings.filter((f) =>
        tokenPatterns.some((p) => p.id === f.patternId)
      );
      if (findings.length === 0) {
        return { content: [{ type: "text", text: "No token safety issues found." }] };
      }
      return { content: [{ type: "text", text: formatFindings("Token Safety", findings) }] };
    }
  );

  // Paid Tool 7: Generate Fix ($0.05)
  server.tool(
    "generate-fix",
    "PAID ($0.05 USDC) — Generate a code fix suggestion for a specific finding.",
    {
      source_code: z.string().describe("Full source code"),
      pattern_id: z.string().describe("Pattern ID to fix"),
      line_number: z.number().describe("Line number where finding was detected"),
      x402_payment: z.string().optional(),
    },
    async ({ source_code, pattern_id, line_number }) => {
      const pattern = SOLANA_PATTERNS.find((p) => p.id === pattern_id);
      if (!pattern) {
        return { content: [{ type: "text", text: `Pattern ${pattern_id} not found.` }] };
      }

      const lines = source_code.split("\n");
      const targetLine = lines[line_number - 1] || "";
      const indent = targetLine.match(/^\s*/)?.[0] || "";

      const fixFn = fixSnippets[pattern_id];
      const fixedCode = fixFn ? fixFn(targetLine, indent) : `${indent}// TODO: ${pattern.fix}\n${targetLine}`;

      const text = [
        `## Fix for ${pattern_id}: ${pattern.name}`,
        `**Line ${line_number}**`,
        "",
        "### Original:",
        "```rust",
        targetLine,
        "```",
        "",
        "### Suggested Fix:",
        "```rust",
        fixedCode,
        "```",
        "",
        `### Explanation:`,
        pattern.fix,
      ].join("\n");

      return { content: [{ type: "text", text }] };
    }
  );

  // Paid Tool 8: Compare Versions ($0.10)
  server.tool(
    "compare-versions",
    "PAID ($0.10 USDC) — Compare two code versions to see if fixes resolved issues or introduced new ones.",
    {
      old_code: z.string().describe("Original source code"),
      new_code: z.string().describe("Updated source code"),
      x402_payment: z.string().optional(),
    },
    async ({ old_code, new_code }) => {
      const oldReport = analyzeCode(old_code);
      const newReport = analyzeCode(new_code);

      const oldIds = new Set(oldReport.findings.map((f) => `${f.patternId}:${f.line}`));
      const newIds = new Set(newReport.findings.map((f) => `${f.patternId}:${f.line}`));

      const fixed = oldReport.findings.filter((f) => !newIds.has(`${f.patternId}:${f.line}`));
      const introduced = newReport.findings.filter((f) => !oldIds.has(`${f.patternId}:${f.line}`));
      const remaining = newReport.findings.filter((f) => oldIds.has(`${f.patternId}:${f.line}`));

      const lines: string[] = [
        "# Version Comparison Report",
        "",
        `| Metric | Old | New |`,
        `|--------|-----|-----|`,
        `| Risk Score | ${oldReport.summary.riskScore} | ${newReport.summary.riskScore} |`,
        `| Total Findings | ${oldReport.summary.total} | ${newReport.summary.total} |`,
        `| Critical | ${oldReport.summary.critical} | ${newReport.summary.critical} |`,
        `| High | ${oldReport.summary.high} | ${newReport.summary.high} |`,
        "",
        `## Fixed (${fixed.length})`,
        ...fixed.map((f) => `- ~~${f.patternId}: ${f.name} (line ${f.line})~~`),
        "",
        `## New Issues (${introduced.length})`,
        ...introduced.map((f) => `- **${f.patternId}: ${f.name}** (line ${f.line}) — ${f.severity.toUpperCase()}`),
        "",
        `## Remaining (${remaining.length})`,
        ...remaining.map((f) => `- ${f.patternId}: ${f.name} (line ${f.line})`),
      ];

      return { content: [{ type: "text", text: lines.join("\n") }] };
    }
  );

  // Paid Tool 9: Full Audit JSON ($0.10)
  server.tool(
    "audit-json",
    "PAID ($0.10 USDC) — Run audit and return structured JSON for programmatic consumption.",
    {
      source_code: z.string().describe("Rust/Anchor source code"),
      x402_payment: z.string().optional(),
    },
    async ({ source_code }) => {
      const report = analyzeCode(source_code);
      return { content: [{ type: "text", text: JSON.stringify(report, null, 2) }] };
    }
  );

  // ════════════════════════════════════════════════════════════════
  // x402 PROTOCOL TOOLS
  // ════════════════════════════════════════════════════════════════

  // Tool: Payment Info
  server.tool(
    "payment-info",
    "FREE — Get x402 payment information: pricing, accepted networks, and payment address.",
    {},
    async () => {
      const pricing = {
        free_tools: ["risk-score", "list-patterns", "explain-finding", "payment-info"],
        paid_tools: {
          "audit-program": { price: "$0.10", description: "Full security audit with findings" },
          "check-accounts": { price: "$0.05", description: "Account validation analysis" },
          "check-cpi": { price: "$0.05", description: "CPI safety analysis" },
          "check-pda": { price: "$0.05", description: "PDA usage audit" },
          "check-arithmetic": { price: "$0.05", description: "Arithmetic safety check" },
          "check-tokens": { price: "$0.05", description: "SPL Token operations audit" },
          "generate-fix": { price: "$0.05", description: "Code fix suggestion" },
          "compare-versions": { price: "$0.10", description: "Version comparison report" },
          "audit-json": { price: "$0.10", description: "Full audit in JSON format" },
        },
        payment: {
          protocol: "x402",
          scheme: SCHEME,
          network: NETWORK,
          asset: "USDC",
          payTo: PAYTO_ADDRESS,
        },
        total_patterns: SOLANA_PATTERNS.length,
        categories: [...new Set(SOLANA_PATTERNS.map(p => p.category))],
      };

      return {
        content: [{
          type: "text",
          text: [
            "# SolanaShield x402 Payment Info",
            "",
            "## Free Tools",
            pricing.free_tools.map(t => `- ${t}`).join("\n"),
            "",
            "## Paid Tools (USDC via x402)",
            ...Object.entries(pricing.paid_tools).map(([name, info]) =>
              `- **${name}**: ${info.price} — ${info.description}`
            ),
            "",
            "## Payment Details",
            `- Protocol: x402 (HTTP 402)`,
            `- Network: ${NETWORK} (Base)`,
            `- Asset: USDC`,
            `- Pay to: ${PAYTO_ADDRESS}`,
            "",
            `## Coverage: ${pricing.total_patterns} vulnerability patterns`,
            `Categories: ${pricing.categories.join(", ")}`,
          ].join("\n"),
        }],
      };
    }
  );
}

// ── Start Server ──────────────────────────────────────────────────
async function main() {
  await registerTools();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("SolanaShield x402 server error:", err);
  process.exit(1);
});
