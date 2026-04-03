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

export const SOLANA_PATTERNS: VulnPattern[] = [
  // === CRITICAL (8) ===
  {
    id: "SOL-C-001",
    name: "Missing Owner Check",
    severity: "critical",
    category: "Access Control",
    description: "Account owner is not validated before use. Attacker can pass arbitrary accounts from malicious programs.",
    keywords: ["owner", "account_info", "key"],
    regex: [
      /AccountInfo.*without.*owner/i,
      /account\.owner\s*!=\s*program_id/,
      /\bAccountInfo\b(?!.*\bowner\b)/,
    ],
    fix: "Add `require!(account.owner == program_id)` or use Anchor's `Account<>` wrapper.",
  },
  {
    id: "SOL-C-002",
    name: "Missing Signer Check",
    severity: "critical",
    category: "Access Control",
    description: "Transaction signer is not verified. Attacker can call instructions without authorization.",
    keywords: ["signer", "is_signer", "authority"],
    regex: [
      /AccountInfo(?!.*is_signer)/,
      /\bauthority\b(?!.*\bSigner\b)/i,
      /invoke_signed(?!.*signer_seeds)/,
    ],
    fix: "Add `require!(authority.is_signer)` or use Anchor's `Signer` type.",
  },
  {
    id: "SOL-C-003",
    name: "Arbitrary CPI (Cross-Program Invocation)",
    severity: "critical",
    category: "CPI Safety",
    description: "CPI target program ID is not validated. Attacker can redirect calls to malicious programs.",
    keywords: ["invoke", "invoke_signed", "program_id", "cpi"],
    regex: [
      /invoke\s*\(\s*[^,]*account/i,
      /invoke_signed\s*\(\s*[^,]*account/i,
      /CpiContext::new\s*\(\s*[^,]*\.to_account_info/,
    ],
    fix: "Validate CPI target: `require!(program.key() == expected_program::ID)`.",
  },
  {
    id: "SOL-C-004",
    name: "PDA Seed Confusion",
    severity: "critical",
    category: "PDA Safety",
    description: "PDA seeds are ambiguous or user-controlled, allowing collisions or spoofing.",
    keywords: ["find_program_address", "create_program_address", "seeds", "bump"],
    regex: [
      /Pubkey::find_program_address.*user_input/i,
      /seeds\s*=\s*\[.*\.key\(\).*\.key\(\)/,
      /create_program_address(?!.*bump)/,
    ],
    fix: "Use fixed-length seeds with domain separators. Store canonical bump. Never use user-controlled data as sole seed.",
  },
  {
    id: "SOL-C-005",
    name: "Account Reinitialization",
    severity: "critical",
    category: "State Safety",
    description: "Account can be initialized multiple times, resetting state and potentially stealing funds.",
    keywords: ["init", "initialize", "is_initialized"],
    regex: [
      /init(?!.*constraint\s*=)/,
      /initialize(?!.*is_initialized)/i,
      /\binit\b(?!.*init_if_needed)/,
    ],
    fix: "Add `is_initialized` flag check or use Anchor `init` constraint (one-time only).",
  },
  {
    id: "SOL-C-006",
    name: "Closing Account Vulnerability",
    severity: "critical",
    category: "State Safety",
    description: "Account close does not zero data or transfer all lamports, enabling revival attacks.",
    keywords: ["close", "lamports", "assign"],
    regex: [
      /close\s*=\s*\w+(?!.*\bassign\b)/,
      /\*\*account\.lamports\.borrow_mut\(\)\s*=\s*0(?!.*data)/,
      /close_account(?!.*zero)/i,
    ],
    fix: "Zero account data, transfer all lamports, and assign to system program on close.",
  },
  {
    id: "SOL-C-007",
    name: "Type Cosplay Attack",
    severity: "critical",
    category: "Deserialization",
    description: "Account type/discriminator is not verified, allowing one account type to impersonate another.",
    keywords: ["deserialize", "try_from_slice", "borsh", "discriminator"],
    regex: [
      /try_from_slice(?!.*discriminator)/i,
      /borsh::.*deserialize(?!.*AccountDiscriminator)/i,
      /unpack(?!.*tag|type|discriminator)/i,
    ],
    fix: "Check 8-byte Anchor discriminator or implement custom type tag verification.",
  },
  {
    id: "SOL-C-008",
    name: "Privilege Escalation via CPI",
    severity: "critical",
    category: "CPI Safety",
    description: "CPI passes elevated signer privileges to untrusted programs.",
    keywords: ["invoke_signed", "signer_seeds", "cpi_context", "with_signer"],
    regex: [
      /invoke_signed.*signer_seeds.*(?:user|input|external)/i,
      /with_signer\s*\(\s*&\[&\[/,
    ],
    fix: "Never pass PDA signer seeds to untrusted programs. Verify CPI target program ID.",
  },

  // === HIGH (12) ===
  {
    id: "SOL-H-001",
    name: "Integer Overflow/Underflow",
    severity: "high",
    category: "Arithmetic",
    description: "Unchecked arithmetic can wrap around, causing incorrect balances or amounts.",
    keywords: ["overflow", "underflow", "checked_add", "checked_sub", "checked_mul"],
    regex: [
      /\+\s*\d+(?!.*checked_add|saturating_add)/,
      /\-\s*\d+(?!.*checked_sub|saturating_sub)/,
      /\*\s*\d+(?!.*checked_mul|saturating_mul)/,
      /as\s+u64(?!.*try_into|checked)/,
    ],
    fix: "Use checked_* or saturating_* arithmetic. Enable overflow-checks in Cargo.toml.",
  },
  {
    id: "SOL-H-002",
    name: "CPI Reentrancy",
    severity: "high",
    category: "CPI Safety",
    description: "State is modified after CPI call, allowing reentrant callbacks to exploit stale state.",
    keywords: ["invoke", "cpi", "reentrancy", "state"],
    regex: [
      /invoke(?:_signed)?\s*\(.*\)[\s\S]{0,200}borrow_mut/,
      /transfer\s*\(.*\)[\s\S]{0,200}amount\s*[+\-=]/,
    ],
    fix: "Follow CEI pattern: Checks → Effects → Interactions. Update state BEFORE CPI calls.",
  },
  {
    id: "SOL-H-003",
    name: "Missing Rent Exemption Check",
    severity: "high",
    category: "State Safety",
    description: "Account may not maintain rent-exempt balance, risking garbage collection.",
    keywords: ["rent", "exempt", "lamports", "minimum_balance"],
    regex: [
      /create_account(?!.*rent|exempt)/i,
      /lamports\s*=\s*0/,
      /transfer(?!.*rent_exempt)/i,
    ],
    fix: "Ensure accounts maintain rent-exempt minimum balance using `Rent::get()?.minimum_balance()`.",
  },
  {
    id: "SOL-H-004",
    name: "Duplicate Mutable Accounts",
    severity: "high",
    category: "Account Safety",
    description: "Same account passed as two mutable parameters, causing double-spend or state corruption.",
    keywords: ["mut", "account_info", "duplicate"],
    regex: [
      /fn\s+\w+\s*\((?:[^)]*mut\s+\w+[^)]*){2,}/,
      /#\[account\(mut\)\][\s\S]*#\[account\(mut\)\]/,
    ],
    fix: "Add `constraint = account_a.key() != account_b.key()` or use Anchor's built-in duplicate detection.",
  },
  {
    id: "SOL-H-005",
    name: "Token Account Authority Mismatch",
    severity: "high",
    category: "Token Safety",
    description: "Token account authority is not verified, allowing unauthorized transfers.",
    keywords: ["authority", "token_account", "mint", "owner"],
    regex: [
      /token_account(?!.*authority|owner|constraint)/i,
      /Transfer\s*\{(?!.*authority)/,
      /transfer_checked(?!.*authority)/,
    ],
    fix: "Verify `token_account.owner == expected_authority`. Use Anchor `token::authority` constraint.",
  },
  {
    id: "SOL-H-006",
    name: "Mint Authority Not Checked",
    severity: "high",
    category: "Token Safety",
    description: "Mint authority is not validated before minting, allowing unauthorized token creation.",
    keywords: ["mint_authority", "mint_to", "mint"],
    regex: [
      /mint_to(?!.*authority)/i,
      /MintTo\s*\{(?!.*authority)/,
    ],
    fix: "Verify `mint.mint_authority == expected_authority` before any mint operation.",
  },
  {
    id: "SOL-H-007",
    name: "Oracle Stale Price (Pyth/Switchboard)",
    severity: "high",
    category: "Oracle Safety",
    description: "Oracle price feed staleness is not checked, allowing use of outdated prices.",
    keywords: ["pyth", "switchboard", "oracle", "price", "staleness"],
    regex: [
      /get_price(?!.*staleness|age|timestamp)/i,
      /oracle(?!.*last_updated|timestamp)/i,
      /price_feed(?!.*get_price_no_older_than)/,
    ],
    fix: "Check `price.publish_time` against `Clock::get()`. Use `get_price_no_older_than()` for Pyth.",
  },
  {
    id: "SOL-H-008",
    name: "Missing Program ID Check in CPI",
    severity: "high",
    category: "CPI Safety",
    description: "CPI target program ID not verified against expected constant.",
    keywords: ["invoke", "program_id", "cpi"],
    regex: [
      /invoke\s*\(&[^,]*,\s*&\[/,
      /CpiContext::new\s*\([^)]*\.to_account_info/,
    ],
    fix: "Check `program.key() == expected_program::id()` before CPI.",
  },
  {
    id: "SOL-H-009",
    name: "Unsafe Deserialization",
    severity: "high",
    category: "Deserialization",
    description: "Account data deserialized without size/bounds validation.",
    keywords: ["deserialize", "try_from_slice", "unpack", "borsh"],
    regex: [
      /try_from_slice\s*\(\s*&data\s*\)/,
      /borsh::try_from_slice(?!.*len|size)/,
    ],
    fix: "Validate data length before deserialization. Check discriminator bytes.",
  },
  {
    id: "SOL-H-010",
    name: "Flash Loan via CPI",
    severity: "high",
    category: "DeFi",
    description: "Balance checked before and after CPI without atomic guarantee, enabling flash loan manipulation.",
    keywords: ["flash", "loan", "balance", "cpi"],
    regex: [
      /balance.*invoke.*balance/i,
      /lamports.*invoke.*lamports/,
    ],
    fix: "Use token account balance snapshots or implement reentrancy guards.",
  },
  {
    id: "SOL-H-011",
    name: "Lamport Transfer Vulnerability",
    severity: "high",
    category: "State Safety",
    description: "Direct lamport manipulation without proper accounting can lead to fund loss.",
    keywords: ["lamports", "borrow_mut", "transfer"],
    regex: [
      /\*\*\w+\.lamports\.borrow_mut\(\)/,
      /try_borrow_mut_lamports/,
    ],
    fix: "Use `system_program::transfer` for lamport transfers. Update state atomically.",
  },
  {
    id: "SOL-H-012",
    name: "Missing Freeze Authority Check",
    severity: "high",
    category: "Token Safety",
    description: "Token account freeze authority not validated, allowing unauthorized freezing.",
    keywords: ["freeze", "authority", "token"],
    regex: [
      /freeze(?!.*authority)/i,
      /FreezeAccount\s*\{(?!.*authority)/,
    ],
    fix: "Verify freeze authority before freeze/thaw operations.",
  },

  // === MEDIUM (12) ===
  {
    id: "SOL-M-001",
    name: "Missing Anchor Constraint",
    severity: "medium",
    category: "Anchor",
    description: "Anchor account constraint is missing, allowing unexpected account state.",
    keywords: ["constraint", "has_one", "seeds", "bump"],
    regex: [
      /#\[account\(\s*\)\]/,
      /#\[account\(\s*mut\s*\)\](?!.*constraint|has_one|seeds)/,
    ],
    fix: "Add appropriate Anchor constraints: `has_one`, `seeds`, `constraint = ...`.",
  },
  {
    id: "SOL-M-002",
    name: "PDA Bump Seed Not Stored",
    severity: "medium",
    category: "PDA Safety",
    description: "PDA canonical bump not stored, causing recalculation on every call (gas waste + potential issues).",
    keywords: ["bump", "find_program_address", "canonical"],
    regex: [
      /find_program_address(?!.*bump.*=)/,
      /Pubkey::find_program_address.*\n(?!.*bump)/,
    ],
    fix: "Store canonical bump in account data. Use `bump = account.bump` in seeds constraint.",
  },
  {
    id: "SOL-M-003",
    name: "Unchecked Remaining Accounts",
    severity: "medium",
    category: "Account Safety",
    description: "remaining_accounts used without validation, allowing injection of arbitrary accounts.",
    keywords: ["remaining_accounts", "ctx.remaining_accounts"],
    regex: [
      /remaining_accounts(?!.*key|owner|check|verify)/i,
      /ctx\.remaining_accounts\[/,
    ],
    fix: "Validate each remaining account's key, owner, and data before use.",
  },
  {
    id: "SOL-M-004",
    name: "Missing Token Program Check",
    severity: "medium",
    category: "Token Safety",
    description: "Token program account not verified as SPL Token or Token-2022 program.",
    keywords: ["token_program", "spl_token", "token_2022"],
    regex: [
      /token_program(?!.*spl_token|token_2022|ID)/i,
      /TokenAccount(?!.*token_program)/i,
    ],
    fix: "Verify `token_program.key() == spl_token::ID` or Token-2022 ID.",
  },
  {
    id: "SOL-M-005",
    name: "Unsafe Account Close",
    severity: "medium",
    category: "State Safety",
    description: "Account close doesn't properly handle all edge cases (data zeroing, reassignment).",
    keywords: ["close", "assign", "zero", "system_program"],
    regex: [
      /close\s*=(?!.*\bsystem_program\b)/,
      /\bclose\b(?!.*zero|data.*0)/i,
    ],
    fix: "Zero data, transfer all lamports to receiver, assign owner to system program.",
  },
  {
    id: "SOL-M-006",
    name: "Precision Loss in Division",
    severity: "medium",
    category: "Arithmetic",
    description: "Integer division before multiplication causes precision loss.",
    keywords: ["precision", "division", "rounding"],
    regex: [
      /\/\s*\d+\s*\*\s*\d+/,
      /\.checked_div.*\.checked_mul/,
    ],
    fix: "Multiply before dividing. Use u128 intermediates for large numbers.",
  },
  {
    id: "SOL-M-007",
    name: "Cross-Instruction State Leak",
    severity: "medium",
    category: "State Safety",
    description: "Account state changes from previous instruction in same transaction not accounted for.",
    keywords: ["reload", "refresh", "stale"],
    regex: [
      /\.reload\(\)(?!.*after_cpi)/i,
    ],
    fix: "Call `account.reload()` after CPI calls that modify the account.",
  },
  {
    id: "SOL-M-008",
    name: "Missing init_if_needed Guard",
    severity: "medium",
    category: "Anchor",
    description: "Using `init_if_needed` without proper reinitialization guard.",
    keywords: ["init_if_needed"],
    regex: [
      /init_if_needed(?!.*constraint)/,
    ],
    fix: "Add `constraint = !account.is_initialized || account.authority == authority.key()`.",
  },
  {
    id: "SOL-M-009",
    name: "Unbounded Iteration",
    severity: "medium",
    category: "DoS",
    description: "Loop over unbounded collection can exceed compute budget.",
    keywords: ["for", "iter", "loop", "compute_budget"],
    regex: [
      /for\s+\w+\s+in\s+\w+\.iter\(\)/,
      /while\s+\w+\s*<\s*\w+\.len\(\)/,
    ],
    fix: "Limit iteration count. Use pagination or off-chain computation for large collections.",
  },
  {
    id: "SOL-M-010",
    name: "Timestamp Dependence",
    severity: "medium",
    category: "Logic",
    description: "Using Clock::get() for time-sensitive operations that validators can manipulate.",
    keywords: ["clock", "unix_timestamp", "slot"],
    regex: [
      /Clock::get\(\).*unix_timestamp/,
      /clock\.unix_timestamp/,
    ],
    fix: "Use slot-based timing when possible. Add tolerance for timestamp-based checks.",
  },
  {
    id: "SOL-M-011",
    name: "Missing Event Emission",
    severity: "medium",
    category: "Observability",
    description: "State-changing instruction doesn't emit events, making off-chain tracking difficult.",
    keywords: ["emit", "event", "log", "msg"],
    regex: [
      /pub fn\s+\w+\s*\((?!.*emit|msg!|sol_log)/,
    ],
    fix: "Add `emit!(EventName { ... })` for all state-changing instructions.",
  },
  {
    id: "SOL-M-012",
    name: "Hardcoded Addresses",
    severity: "medium",
    category: "Configuration",
    description: "Program addresses hardcoded instead of using configurable state.",
    keywords: ["pubkey", "hardcoded", "address"],
    regex: [
      /Pubkey::new_from_array\s*\(\s*\[/,
      /solana_program::pubkey!\s*\("/,
    ],
    fix: "Use PDA-derived or configurable addresses stored in program state.",
  },

  // === LOW (8) ===
  {
    id: "SOL-L-001",
    name: "Missing Error Context",
    severity: "low",
    category: "Error Handling",
    description: "Error messages lack context, making debugging difficult.",
    keywords: ["error", "err", "ProgramError"],
    regex: [
      /return Err\(ProgramError::\w+\)/,
      /\.ok_or\(ProgramError/,
    ],
    fix: "Use custom error types with descriptive messages via `#[error_code]`.",
  },
  {
    id: "SOL-L-002",
    name: "Unused Accounts in Instruction",
    severity: "low",
    category: "Optimization",
    description: "Accounts passed to instruction but never used, wasting transaction space.",
    keywords: ["unused", "account"],
    regex: [
      /\/\/\/\s*CHECK:.*not used/i,
      /UncheckedAccount.*unused/i,
    ],
    fix: "Remove unused accounts from instruction context.",
  },
  {
    id: "SOL-L-003",
    name: "Missing Instruction Logging",
    severity: "low",
    category: "Observability",
    description: "No msg! or sol_log calls for debugging and monitoring.",
    keywords: ["msg", "log", "sol_log"],
    regex: [
      /pub fn\s+\w+\s*\([^)]*\)\s*->[^{]*\{(?![\s\S]{0,50}msg!)/,
    ],
    fix: "Add `msg!(\"instruction_name: params\")` at function entry.",
  },
  {
    id: "SOL-L-004",
    name: "Magic Numbers",
    severity: "low",
    category: "Code Quality",
    description: "Literal numbers used instead of named constants.",
    keywords: ["const", "magic", "literal"],
    regex: [
      /\b(?:100|1000|10000|86400|3600)\b(?!.*const)/,
    ],
    fix: "Extract magic numbers to named constants.",
  },
  {
    id: "SOL-L-005",
    name: "CU Optimization Opportunity",
    severity: "low",
    category: "Optimization",
    description: "Compute units can be reduced with minor optimizations.",
    keywords: ["compute", "CU", "optimization"],
    regex: [
      /\.to_string\(\)(?!.*display)/i,
      /format!\s*\(/,
      /clone\(\).*clone\(\)/,
    ],
    fix: "Avoid allocations in hot paths. Use borsh serialization directly.",
  },
  {
    id: "SOL-L-006",
    name: "Deprecated API Usage",
    severity: "low",
    category: "Maintenance",
    description: "Using deprecated Solana/Anchor APIs.",
    keywords: ["deprecated", "legacy"],
    regex: [
      /spl_token::instruction::transfer\b(?!_checked)/,
      /associated_token::create\b(?!_idempotent)/,
    ],
    fix: "Use `transfer_checked` instead of `transfer`. Use `create_idempotent` for ATA.",
  },
  {
    id: "SOL-L-007",
    name: "Test-Only Code in Production",
    severity: "low",
    category: "Code Quality",
    description: "Test utilities or debug code present in non-test modules.",
    keywords: ["test", "debug", "todo", "fixme"],
    regex: [
      /(?:TODO|FIXME|HACK|XXX):/i,
      /#\[cfg\(not\(test\)\)\].*(?:debug|print)/i,
    ],
    fix: "Remove test-only code. Use `#[cfg(test)]` properly.",
  },
  {
    id: "SOL-L-008",
    name: "Missing Documentation",
    severity: "low",
    category: "Code Quality",
    description: "Public functions or types lack documentation.",
    keywords: ["doc", "///", "comment"],
    regex: [
      /pub\s+(?:fn|struct|enum)\s+\w+(?![\s\S]{0,5}\/\/\/)/,
    ],
    fix: "Add `/// Documentation` above all public items.",
  },
];

export function getPatternsBySeverity(severity: VulnPattern["severity"]): VulnPattern[] {
  return SOLANA_PATTERNS.filter((p) => p.severity === severity);
}

export function getPatternsByCategory(category: string): VulnPattern[] {
  return SOLANA_PATTERNS.filter((p) => p.category.toLowerCase() === category.toLowerCase());
}
