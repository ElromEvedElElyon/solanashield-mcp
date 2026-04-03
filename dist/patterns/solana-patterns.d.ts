/**
 * SolanaShield — 40+ Solana-specific vulnerability patterns
 * Ported and extended from Israel/Four VULN_DB + CyberSentinel patterns
 */
export interface VulnPattern {
    id: string;
    name: string;
    severity: "critical" | "high" | "medium" | "low";
    category: string;
    description: string;
    keywords: string[];
    regex: RegExp[];
    fix: string;
}
export declare const SOLANA_PATTERNS: VulnPattern[];
export declare function getPatternsBySeverity(severity: VulnPattern["severity"]): VulnPattern[];
export declare function getPatternsByCategory(category: string): VulnPattern[];
