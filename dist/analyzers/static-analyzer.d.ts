/**
 * SolanaShield Static Analyzer
 * Pattern-matching engine for Solana program vulnerability detection
 */
import { VulnPattern } from "../patterns/solana-patterns.js";
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
    context: string;
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
        riskScore: number;
    };
}
export declare function analyzeCode(sourceCode: string, filterSeverity?: VulnPattern["severity"][]): AuditReport;
export declare function formatReport(report: AuditReport): string;
export declare function checkAccounts(sourceCode: string): Finding[];
export declare function checkCPI(sourceCode: string): Finding[];
export declare function checkPDA(sourceCode: string): Finding[];
export declare function checkArithmetic(sourceCode: string): Finding[];
