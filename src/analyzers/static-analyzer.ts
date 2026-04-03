/**
 * SolanaShield Static Analyzer
 * Pattern-matching engine for Solana program vulnerability detection
 */

import { SOLANA_PATTERNS, VulnPattern, getPatternsBySeverity } from "../patterns/solana-patterns.js";

export interface Finding {
  patternId: string;
  name: string;
  severity: VulnPattern["severity"];
  category: string;
  description: string;
  fix: string;
  line: number;
  column: number;
  matchedText: string;
  context: string; // surrounding lines
}

export interface AuditReport {
  timestamp: string;
  linesAnalyzed: number;
  patternsChecked: number;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
    riskScore: number; // 0-100
  };
}

function getContext(lines: string[], lineIdx: number, range = 2): string {
  const start = Math.max(0, lineIdx - range);
  const end = Math.min(lines.length - 1, lineIdx + range);
  const result: string[] = [];
  for (let i = start; i <= end; i++) {
    const marker = i === lineIdx ? ">>>" : "   ";
    result.push(`${marker} ${i + 1} | ${lines[i]}`);
  }
  return result.join("\n");
}

export function analyzeCode(sourceCode: string, filterSeverity?: VulnPattern["severity"][]): AuditReport {
  const lines = sourceCode.split("\n");
  const findings: Finding[] = [];

  const patterns = filterSeverity
    ? filterSeverity.flatMap((s) => getPatternsBySeverity(s))
    : SOLANA_PATTERNS;

  for (const pattern of patterns) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Skip comments
      if (line.trimStart().startsWith("//") || line.trimStart().startsWith("*")) continue;

      for (const re of pattern.regex) {
        const match = re.exec(line);
        if (match) {
          // Avoid duplicate findings on same line for same pattern
          if (findings.some((f) => f.patternId === pattern.id && f.line === i + 1)) break;

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

export function formatReport(report: AuditReport): string {
  const lines: string[] = [];
  const { summary } = report;

  lines.push("# SolanaShield Security Audit Report");
  lines.push(`**Timestamp**: ${report.timestamp}`);
  lines.push(`**Lines Analyzed**: ${report.linesAnalyzed}`);
  lines.push(`**Patterns Checked**: ${report.patternsChecked}`);
  lines.push("");

  // Risk gauge
  const riskLabel =
    summary.riskScore >= 75 ? "CRITICAL" :
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
    const icon =
      f.severity === "critical" ? "[CRITICAL]" :
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

export function checkAccounts(sourceCode: string): Finding[] {
  const accountPatterns = SOLANA_PATTERNS.filter((p) =>
    ["Access Control", "Account Safety", "Token Safety"].includes(p.category)
  );
  const report = analyzeCode(sourceCode, undefined);
  return report.findings.filter((f) =>
    accountPatterns.some((p) => p.id === f.patternId)
  );
}

export function checkCPI(sourceCode: string): Finding[] {
  const cpiPatterns = SOLANA_PATTERNS.filter((p) => p.category === "CPI Safety");
  const report = analyzeCode(sourceCode, undefined);
  return report.findings.filter((f) =>
    cpiPatterns.some((p) => p.id === f.patternId)
  );
}

export function checkPDA(sourceCode: string): Finding[] {
  const pdaPatterns = SOLANA_PATTERNS.filter((p) => p.category === "PDA Safety");
  const report = analyzeCode(sourceCode, undefined);
  return report.findings.filter((f) =>
    pdaPatterns.some((p) => p.id === f.patternId)
  );
}

export function checkArithmetic(sourceCode: string): Finding[] {
  const mathPatterns = SOLANA_PATTERNS.filter((p) => p.category === "Arithmetic");
  const report = analyzeCode(sourceCode, undefined);
  return report.findings.filter((f) =>
    mathPatterns.some((p) => p.id === f.patternId)
  );
}
