"use strict";
/**
 * SolanaShield Static Analyzer
 * Pattern-matching engine for Solana program vulnerability detection
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeCode = analyzeCode;
exports.formatReport = formatReport;
exports.checkAccounts = checkAccounts;
exports.checkCPI = checkCPI;
exports.checkPDA = checkPDA;
exports.checkArithmetic = checkArithmetic;
const solana_patterns_js_1 = require("../patterns/solana-patterns.js");
function getContext(lines, lineIdx, range = 2) {
    const start = Math.max(0, lineIdx - range);
    const end = Math.min(lines.length - 1, lineIdx + range);
    const result = [];
    for (let i = start; i <= end; i++) {
        const marker = i === lineIdx ? ">>>" : "   ";
        result.push(`${marker} ${i + 1} | ${lines[i]}`);
    }
    return result.join("\n");
}
function analyzeCode(sourceCode, filterSeverity) {
    const lines = sourceCode.split("\n");
    const findings = [];
    const patterns = filterSeverity
        ? filterSeverity.flatMap((s) => (0, solana_patterns_js_1.getPatternsBySeverity)(s))
        : solana_patterns_js_1.SOLANA_PATTERNS;
    for (const pattern of patterns) {
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            // Skip comments
            if (line.trimStart().startsWith("//") || line.trimStart().startsWith("*"))
                continue;
            for (const re of pattern.regex) {
                const match = re.exec(line);
                if (match) {
                    // Avoid duplicate findings on same line for same pattern
                    if (findings.some((f) => f.patternId === pattern.id && f.line === i + 1))
                        break;
                    findings.push({
                        patternId: pattern.id,
                        name: pattern.name,
                        severity: pattern.severity,
                        category: pattern.category,
                        description: pattern.description,
                        fix: pattern.fix,
                        line: i + 1,
                        column: match.index + 1,
                        matchedText: match[0],
                        context: getContext(lines, i),
                    });
                    break; // one match per pattern per line
                }
            }
        }
    }
    // Sort: critical first, then by line
    findings.sort((a, b) => {
        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        const sevDiff = sevOrder[a.severity] - sevOrder[b.severity];
        return sevDiff !== 0 ? sevDiff : a.line - b.line;
    });
    const critical = findings.filter((f) => f.severity === "critical").length;
    const high = findings.filter((f) => f.severity === "high").length;
    const medium = findings.filter((f) => f.severity === "medium").length;
    const low = findings.filter((f) => f.severity === "low").length;
    const total = findings.length;
    // Risk score: weighted sum capped at 100
    const riskScore = Math.min(100, critical * 25 + high * 10 + medium * 4 + low * 1);
    return {
        timestamp: new Date().toISOString(),
        linesAnalyzed: lines.length,
        patternsChecked: patterns.length,
        findings,
        summary: { critical, high, medium, low, total, riskScore },
    };
}
function formatReport(report) {
    const lines = [];
    const { summary } = report;
    lines.push("# SolanaShield Security Audit Report");
    lines.push(`**Timestamp**: ${report.timestamp}`);
    lines.push(`**Lines Analyzed**: ${report.linesAnalyzed}`);
    lines.push(`**Patterns Checked**: ${report.patternsChecked}`);
    lines.push("");
    // Risk gauge
    const riskLabel = summary.riskScore >= 75 ? "CRITICAL" :
        summary.riskScore >= 50 ? "HIGH" :
            summary.riskScore >= 25 ? "MEDIUM" : "LOW";
    lines.push(`## Risk Score: ${summary.riskScore}/100 (${riskLabel})`);
    lines.push("");
    lines.push(`| Severity | Count |`);
    lines.push(`|----------|-------|`);
    lines.push(`| Critical | ${summary.critical} |`);
    lines.push(`| High     | ${summary.high} |`);
    lines.push(`| Medium   | ${summary.medium} |`);
    lines.push(`| Low      | ${summary.low} |`);
    lines.push(`| **Total**| **${summary.total}** |`);
    lines.push("");
    if (report.findings.length === 0) {
        lines.push("No vulnerabilities detected. Code appears safe based on pattern analysis.");
        return lines.join("\n");
    }
    lines.push("## Findings");
    lines.push("");
    for (const f of report.findings) {
        const icon = f.severity === "critical" ? "[CRITICAL]" :
            f.severity === "high" ? "[HIGH]" :
                f.severity === "medium" ? "[MEDIUM]" : "[LOW]";
        lines.push(`### ${icon} ${f.patternId}: ${f.name}`);
        lines.push(`**Line ${f.line}** | Category: ${f.category}`);
        lines.push("");
        lines.push(f.description);
        lines.push("");
        lines.push("```rust");
        lines.push(f.context);
        lines.push("```");
        lines.push("");
        lines.push(`**Fix**: ${f.fix}`);
        lines.push("---");
        lines.push("");
    }
    return lines.join("\n");
}
function checkAccounts(sourceCode) {
    const accountPatterns = solana_patterns_js_1.SOLANA_PATTERNS.filter((p) => ["Access Control", "Account Safety", "Token Safety"].includes(p.category));
    const report = analyzeCode(sourceCode, undefined);
    return report.findings.filter((f) => accountPatterns.some((p) => p.id === f.patternId));
}
function checkCPI(sourceCode) {
    const cpiPatterns = solana_patterns_js_1.SOLANA_PATTERNS.filter((p) => p.category === "CPI Safety");
    const report = analyzeCode(sourceCode, undefined);
    return report.findings.filter((f) => cpiPatterns.some((p) => p.id === f.patternId));
}
function checkPDA(sourceCode) {
    const pdaPatterns = solana_patterns_js_1.SOLANA_PATTERNS.filter((p) => p.category === "PDA Safety");
    const report = analyzeCode(sourceCode, undefined);
    return report.findings.filter((f) => pdaPatterns.some((p) => p.id === f.patternId));
}
function checkArithmetic(sourceCode) {
    const mathPatterns = solana_patterns_js_1.SOLANA_PATTERNS.filter((p) => p.category === "Arithmetic");
    const report = analyzeCode(sourceCode, undefined);
    return report.findings.filter((f) => mathPatterns.some((p) => p.id === f.patternId));
}
//# sourceMappingURL=static-analyzer.js.map