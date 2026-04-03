#!/usr/bin/env node
"use strict";
/**
 * SolanaShield MCP Server
 * AI-powered smart contract security for Solana programs
 *
 * 12 MCP tools for comprehensive Solana security analysis
 */
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const static_analyzer_js_1 = require("./analyzers/static-analyzer.js");
const solana_patterns_js_1 = require("./patterns/solana-patterns.js");
const server = new mcp_js_1.McpServer({
    name: "solanashield",
    version: "1.0.0",
});
// ── Tool 1: Full Audit ─────────────────────────────────────────────
server.tool("audit-program", "Run a full security audit on Solana/Anchor program source code. Returns findings sorted by severity with fix suggestions.", {
    source_code: zod_1.z.string().describe("Rust/Anchor source code to audit"),
    severity_filter: zod_1.z
        .array(zod_1.z.enum(["critical", "high", "medium", "low"]))
        .optional()
        .describe("Filter by severity levels (default: all)"),
}, async ({ source_code, severity_filter }) => {
    const report = (0, static_analyzer_js_1.analyzeCode)(source_code, severity_filter);
    return { content: [{ type: "text", text: (0, static_analyzer_js_1.formatReport)(report) }] };
});
// ── Tool 2: Check Accounts ─────────────────────────────────────────
server.tool("check-accounts", "Check account validation: owner checks, signer verification, authority, token accounts, duplicate mutable accounts.", {
    source_code: zod_1.z.string().describe("Rust/Anchor source code"),
}, async ({ source_code }) => {
    const findings = (0, static_analyzer_js_1.checkAccounts)(source_code);
    if (findings.length === 0) {
        return { content: [{ type: "text", text: "No account validation issues found." }] };
    }
    return {
        content: [{ type: "text", text: formatFindings("Account Validation", findings) }],
    };
});
// ── Tool 3: Check CPI ──────────────────────────────────────────────
server.tool("check-cpi", "Analyze Cross-Program Invocations for safety: arbitrary CPI, reentrancy, privilege escalation, program ID validation.", {
    source_code: zod_1.z.string().describe("Rust/Anchor source code"),
}, async ({ source_code }) => {
    const findings = (0, static_analyzer_js_1.checkCPI)(source_code);
    if (findings.length === 0) {
        return { content: [{ type: "text", text: "No CPI safety issues found." }] };
    }
    return {
        content: [{ type: "text", text: formatFindings("CPI Safety", findings) }],
    };
});
// ── Tool 4: Check PDA ──────────────────────────────────────────────
server.tool("check-pda", "Audit PDA (Program Derived Address) usage: seed confusion, bump storage, collisions.", {
    source_code: zod_1.z.string().describe("Rust/Anchor source code"),
}, async ({ source_code }) => {
    const findings = (0, static_analyzer_js_1.checkPDA)(source_code);
    if (findings.length === 0) {
        return { content: [{ type: "text", text: "No PDA safety issues found." }] };
    }
    return {
        content: [{ type: "text", text: formatFindings("PDA Safety", findings) }],
    };
});
// ── Tool 5: Check Arithmetic ───────────────────────────────────────
server.tool("check-arithmetic", "Detect integer overflow/underflow, precision loss, and unsafe type casting.", {
    source_code: zod_1.z.string().describe("Rust/Anchor source code"),
}, async ({ source_code }) => {
    const findings = (0, static_analyzer_js_1.checkArithmetic)(source_code);
    if (findings.length === 0) {
        return { content: [{ type: "text", text: "No arithmetic safety issues found." }] };
    }
    return {
        content: [{ type: "text", text: formatFindings("Arithmetic Safety", findings) }],
    };
});
// ── Tool 6: Risk Score ─────────────────────────────────────────────
server.tool("risk-score", "Calculate a 0-100 risk score for Solana program code. Quick triage without full details.", {
    source_code: zod_1.z.string().describe("Rust/Anchor source code"),
}, async ({ source_code }) => {
    const report = (0, static_analyzer_js_1.analyzeCode)(source_code);
    const { summary } = report;
    const riskLabel = summary.riskScore >= 75 ? "CRITICAL" :
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
    ].join("\n");
    return { content: [{ type: "text", text }] };
});
// ── Tool 7: List Patterns ──────────────────────────────────────────
server.tool("list-patterns", "List all vulnerability patterns SolanaShield checks for, optionally filtered by severity or category.", {
    severity: zod_1.z.enum(["critical", "high", "medium", "low"]).optional(),
    category: zod_1.z.string().optional().describe("Filter by category (e.g., 'CPI Safety', 'Token Safety')"),
}, async ({ severity, category }) => {
    let patterns = solana_patterns_js_1.SOLANA_PATTERNS;
    if (severity)
        patterns = (0, solana_patterns_js_1.getPatternsBySeverity)(severity);
    if (category)
        patterns = (0, solana_patterns_js_1.getPatternsByCategory)(category);
    const text = patterns
        .map((p) => `[${p.severity.toUpperCase()}] ${p.id}: ${p.name}\n  ${p.description}`)
        .join("\n\n");
    return {
        content: [
            {
                type: "text",
                text: `SolanaShield Patterns (${patterns.length} total):\n\n${text}`,
            },
        ],
    };
});
// ── Tool 8: Explain Finding ────────────────────────────────────────
server.tool("explain-finding", "Get detailed explanation, exploit scenario, and remediation for a specific vulnerability pattern.", {
    pattern_id: zod_1.z.string().describe("Pattern ID (e.g., SOL-C-001)"),
}, async ({ pattern_id }) => {
    const pattern = solana_patterns_js_1.SOLANA_PATTERNS.find((p) => p.id === pattern_id);
    if (!pattern) {
        return {
            content: [{ type: "text", text: `Pattern ${pattern_id} not found. Use list-patterns to see available IDs.` }],
        };
    }
    const exploitScenarios = {
        "SOL-C-001": "1. Attacker creates a fake account owned by their malicious program\n2. Passes it as a legitimate account to the vulnerable instruction\n3. Program reads attacker-controlled data, leading to fund theft",
        "SOL-C-002": "1. Attacker crafts transaction without signing as authority\n2. Instruction executes privileged operation (transfer, close, etc.)\n3. Attacker drains funds without authorization",
        "SOL-C-003": "1. Attacker passes their own program ID instead of expected program\n2. CPI redirects to malicious program\n3. Malicious program returns fake success, steals seeds/authority",
        "SOL-C-004": "1. Attacker finds two different inputs that derive same PDA\n2. Uses one PDA for initialization, another for exploitation\n3. Gains unauthorized access to program state",
        "SOL-C-005": "1. Attacker calls initialize on already-initialized account\n2. State resets to default values\n3. Attacker exploits fresh state (e.g., reset admin, steal deposited funds)",
        "SOL-C-006": "1. Attacker closes account (transfers lamports)\n2. In same transaction, sends lamports back to revive account\n3. Account data persists in stale state, enabling double-spend",
        "SOL-C-007": "1. Attacker creates account with correct data layout but wrong type\n2. Program deserializes it as expected type (e.g., Vault treated as Config)\n3. Attacker manipulates program logic via type confusion",
        "SOL-C-008": "1. Attacker calls program that passes PDA signer seeds via CPI\n2. CPI target is malicious program that captures signer authority\n3. Malicious program signs transactions as the PDA",
    };
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
});
// ── Tool 9: Compare Versions ───────────────────────────────────────
server.tool("compare-versions", "Compare two versions of code to see if fixes resolved previous findings or introduced new issues.", {
    old_code: zod_1.z.string().describe("Original source code"),
    new_code: zod_1.z.string().describe("Updated source code"),
}, async ({ old_code, new_code }) => {
    const oldReport = (0, static_analyzer_js_1.analyzeCode)(old_code);
    const newReport = (0, static_analyzer_js_1.analyzeCode)(new_code);
    const oldIds = new Set(oldReport.findings.map((f) => `${f.patternId}:${f.line}`));
    const newIds = new Set(newReport.findings.map((f) => `${f.patternId}:${f.line}`));
    const fixed = oldReport.findings.filter((f) => !newIds.has(`${f.patternId}:${f.line}`));
    const introduced = newReport.findings.filter((f) => !oldIds.has(`${f.patternId}:${f.line}`));
    const remaining = newReport.findings.filter((f) => oldIds.has(`${f.patternId}:${f.line}`));
    const lines = [
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
});
// ── Tool 10: Generate Fix ──────────────────────────────────────────
server.tool("generate-fix", "Generate a code fix suggestion for a specific finding at a given line.", {
    source_code: zod_1.z.string().describe("Full source code"),
    pattern_id: zod_1.z.string().describe("Pattern ID to fix (e.g., SOL-C-001)"),
    line_number: zod_1.z.number().describe("Line number where the finding was detected"),
}, async ({ source_code, pattern_id, line_number }) => {
    const pattern = solana_patterns_js_1.SOLANA_PATTERNS.find((p) => p.id === pattern_id);
    if (!pattern) {
        return { content: [{ type: "text", text: `Pattern ${pattern_id} not found.` }] };
    }
    const lines = source_code.split("\n");
    const targetLine = lines[line_number - 1] || "";
    const indent = targetLine.match(/^\s*/)?.[0] || "";
    const fixSnippets = {
        "SOL-C-001": (l, ind) => `${ind}// SolanaShield fix: Add owner check\n${ind}require!(account.owner == &program_id, ErrorCode::InvalidOwner);\n${l}`,
        "SOL-C-002": (l, ind) => `${ind}// SolanaShield fix: Add signer check\n${ind}require!(authority.is_signer, ErrorCode::MissingSigner);\n${l}`,
        "SOL-C-003": (l, ind) => `${ind}// SolanaShield fix: Validate CPI target\n${ind}require!(program.key() == expected_program::ID, ErrorCode::InvalidProgram);\n${l}`,
        "SOL-H-001": (l, _ind) => l
            .replace(/(\w+)\s*\+\s*(\w+)/, "$1.checked_add($2).ok_or(ErrorCode::Overflow)?")
            .replace(/(\w+)\s*-\s*(\w+)/, "$1.checked_sub($2).ok_or(ErrorCode::Underflow)?")
            .replace(/(\w+)\s*\*\s*(\w+)/, "$1.checked_mul($2).ok_or(ErrorCode::Overflow)?"),
    };
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
});
// ── Tool 11: Check Token Safety ────────────────────────────────────
server.tool("check-tokens", "Analyze SPL Token operations: authority checks, mint validation, freeze authority, token-2022 compatibility.", {
    source_code: zod_1.z.string().describe("Rust/Anchor source code"),
}, async ({ source_code }) => {
    const tokenPatterns = solana_patterns_js_1.SOLANA_PATTERNS.filter((p) => p.category === "Token Safety");
    const report = (0, static_analyzer_js_1.analyzeCode)(source_code);
    const findings = report.findings.filter((f) => tokenPatterns.some((p) => p.id === f.patternId));
    if (findings.length === 0) {
        return { content: [{ type: "text", text: "No token safety issues found." }] };
    }
    return {
        content: [{ type: "text", text: formatFindings("Token Safety", findings) }],
    };
});
// ── Tool 12: Audit Summary (JSON) ──────────────────────────────────
server.tool("audit-json", "Run audit and return structured JSON results for programmatic consumption.", {
    source_code: zod_1.z.string().describe("Rust/Anchor source code"),
}, async ({ source_code }) => {
    const report = (0, static_analyzer_js_1.analyzeCode)(source_code);
    return {
        content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
    };
});
// ── Helper ─────────────────────────────────────────────────────────
function formatFindings(title, findings) {
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
// ── Start Server ───────────────────────────────────────────────────
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
}
main().catch((err) => {
    console.error("SolanaShield MCP server error:", err);
    process.exit(1);
});
//# sourceMappingURL=index.js.map