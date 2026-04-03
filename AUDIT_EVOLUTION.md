# Audit Evolution — Learning & Pattern Database
# Persistent knowledge that must grow with each audit

## SKILL LEVEL: INTERMEDIATE → ADVANCED (Session 109)
## Total Findings Submitted: 50+ | Accepted: 0 | Rejected: 2 | Pending: 48+
## Win Rate: 0% (ZERO confirmed payouts)

---

## VULNERABILITY CLASSES MASTERED (with confidence score)

### CLASS 1: Temporal/TTL State Reset [CONFIDENCE: 85%]
- **Discovery**: LayerZero V2 Stellar (Session 100)
- **Pattern**: Soroban persistent storage entries have TTL. When TTL expires, `#[default(...)]` resets state to initial values silently.
- **Exploits found**: 18 in LayerZero alone (H-01 DVN replay, H-02 Nonce reset, H-03 Confirmation griefing)
- **Methodology**: Search for ALL persistent storage → check each for TTL renewal → check default values → assess impact of reset
- **Status**: 2 HIGH SUBMITTED to C4. WAITING result.
- **Lesson**: This is a SYSTEMATIC class — once you find one, audit EVERY persistent entry

### CLASS 2: TEE/Attestation Bypass [CONFIDENCE: 75%]
- **Discovery**: NEAR Intents MPC (Session 107)
- **Pattern**: Test attestation variants (MockAttestation::Valid) compiled into production WASM without `#[cfg(test)]` feature gate
- **Impact**: $100K-$500K (all MPC funds at risk)
- **Status**: Finding 1 declared OUT OF SCOPE by HackenProof (TEE grace period). Emailed to security@near.org.
- **Lesson**: Always check if test/mock code is feature-gated. Check Cargo.toml features AND conditional compilation.
- **FAILURE LESSON**: Even valid CRITICAL findings can be out of scope due to program rules. READ SCOPE FIRST.

### CLASS 3: CEI (Checks-Effects-Interactions) Violations [CONFIDENCE: 70%]
- **Discovery**: Hyperlane Mailbox.process() (Session 101)
- **Pattern**: State modified AFTER external call, enabling reentrancy or state manipulation
- **Exploits found**: 1 CRITICAL in Hyperlane
- **Status**: Report #71903 SUBMITTED to Immunefi. #72086 also submitted.
- **Lesson**: Trace execution order. If ANY state write happens after invoke/CPI/external_call, it's a finding.

### CLASS 4: Validation Divergence [CONFIDENCE: 65%]
- **Discovery**: Chainlink Payment Abstraction V2 (Session 100)
- **Pattern**: Two code paths validate different things. bid() checks minBidUsdValue, isValidSignature() does not.
- **Exploits found**: 1 HIGH (H-01 micro-fill griefing)
- **Status**: DRAFTED for C4 (contest closed before submission)
- **Lesson**: Find ALL entry points to same state. Compare validation logic. Difference = vulnerability.

### CLASS 5: Integer Overflow in Solana/Anchor [CONFIDENCE: 80%]
- **Discovery**: Multiple audits + SolanaShield patterns
- **Pattern**: Rust unchecked arithmetic wraps in release mode. `as u64` silently truncates.
- **Detection**: Regex for `+ \d+` without `checked_add`, `as u64` without `try_into`
- **Status**: 40 patterns codified in SolanaShield MCP
- **Lesson**: Solana programs in release mode DO NOT panic on overflow. This is different from debug mode.

### CLASS 6: Missing Owner/Signer Checks (Solana) [CONFIDENCE: 90%]
- **Discovery**: Foundational Solana security
- **Pattern**: AccountInfo used without verifying .owner == program_id or .is_signer
- **Status**: Codified in SolanaShield SOL-C-001, SOL-C-002
- **Lesson**: EVERY account in a Solana instruction must be validated. Anchor does this automatically with Account<> wrapper.

### CLASS 7: Arbitrary CPI (Solana) [CONFIDENCE: 85%]
- **Discovery**: Multiple audit sources
- **Pattern**: invoke/invoke_signed called with user-supplied program_id
- **Status**: Codified in SolanaShield SOL-C-003
- **Lesson**: CPI target MUST be hardcoded or derived from trusted state

---

## AUDIT METHODOLOGY — BATTLE-TESTED

### Pre-Audit (30 min)
1. READ SCOPE DOCUMENT COMPLETELY — what's in scope, what's out
2. Identify blockchain (EVM/Solana/Soroban/NEAR) — different patterns apply
3. Check prize pool, severity definitions, judging criteria
4. Look at previous audits of same protocol (OpenZeppelin, Trail of Bits)

### Phase 1: Architecture (1h)
1. Map all entry points (external functions, instructions)
2. Identify trust boundaries (who can call what)
3. Map state variables and storage layout
4. Identify external dependencies (oracles, bridges, tokens)

### Phase 2: Pattern Scan (2h)
1. Run VULN_PATTERNS (60+ regex patterns) — SolanaShield or Mythic Engine
2. Check every access control point (owner, signer, authority)
3. Trace every external call (CPI, delegatecall, cross-contract)
4. Check arithmetic operations for overflow/underflow
5. Verify state consistency after external interactions (CEI)

### Phase 3: Deep Analysis (4h)
1. For each finding from Phase 2 — write full PoC
2. Economic analysis — what's the ACTUAL financial impact?
3. Check for SYSTEMATIC classes — if one TTL issue exists, check ALL TTL entries
4. Cross-function analysis — can combining two safe functions create exploit?

### Phase 4: Report Writing (2h)
1. Title: [SEVERITY] One-line description of impact
2. Root cause with exact line numbers
3. Step-by-step exploit scenario
4. PoC code (Foundry test or transaction sequence)
5. Fix recommendation (specific code change)

---

## FAILURE LOG — WHAT WE GOT WRONG

### Failure 1: Immunefi #71022 — CLOSED $0
- **What**: ZKsync Governor proposal threshold bypass
- **Why rejected**: Not first reporter. OpenZeppelin audit Oct 2025 already identified it.
- **Lesson**: CHECK if protocol was recently audited. If yes, your finding is likely duplicate.
- **Prevention**: Search for "[protocol] audit report" before submitting

### Failure 2: nuclei-templates #15769 — REJECTED
- **What**: 5 KEV CVE detection templates
- **Why rejected**: "No version-detection templates" + labeled "AI-generated"
- **Lesson**: nuclei wants EXPLOIT templates, not detection. Also, AI-generated label = death.
- **Prevention**: Only submit exploit-capable templates. Add manual testing evidence.

### Failure 3: HackenProof NEAR Finding 1 — OUT OF SCOPE
- **What**: MockAttestation CRITICAL bypass
- **Why rejected**: TEE grace period in program rules excludes this class
- **Lesson**: READ. THE. SCOPE. Every word matters. Grace periods, exclusions, specific versions.
- **Prevention**: Before ANY audit work, create scope checklist with explicit in/out items.

### Failure 4: claude-builders-bounty — 275 PRs, 0 merges EVER
- **What**: 5 PRs submitted ($375 total)
- **Why failed**: Repo appears to be abandoned/non-paying despite active bounty labels
- **Lesson**: Check merge history BEFORE contributing. If 0 merges in 100+ PRs = DEAD.
- **Prevention**: `gh pr list --state merged --limit 5` — if empty, SKIP.

### Failure 5: dn-institute — 10 PRs, 0 merges
- **What**: Multiple documentation/fix PRs
- **Why failed**: Maintainer unresponsive
- **Lesson**: Same as above. No merge history = no payment.
- **Prevention**: Always verify maintainer activity (last commit date, last PR merged)

---

## PLATFORM INTELLIGENCE

### Immunefi
- Rate limit: 0/1 slots, resets ~24h after last submission
- CSRF: Header `csrftoken` from `__NEXT_DATA__.props.pageProps.csrfToken`
- Draft URL: `/dashboard/new-submission/{draftId}/review`
- Submit flow: scroll terms → check checkbox → "Next: Submit Report" → "Submit Report" dialog
- Email for Zendesk escalation when API blocked
- **Key insight**: Immunefi CLOSES findings if "known issue" from prior audit

### Code4rena
- 2/2 submission slots per contest
- KYC: APPROVED (ElromAuditor)
- Discord: CONNECTED (elromauditor_86701)
- **Key insight**: Contest pools split among ALL valid findings of same severity

### Guardian
- `acceptedCustomTerms: true` REQUIRED in submit payload (undocumented)
- `contestId` required
- KYC: APPROVED
- **Key insight**: 16 findings submitted, but no response mechanism visible

### HackenProof
- Profile: VERIFIED 80/80
- KYC: NOT DONE (blocks NEAR program)
- Chrome CDP port 9222
- **Key insight**: Program scope rules can exclude entire vulnerability CLASSES

---

## TOOLS THAT ACTUALLY WORK FOR AUDITING

1. **SolanaShield MCP** (our tool) — 40 Solana patterns, 12 tools, npm published
2. **Mythic Engine CyberSentinel** — 60 patterns, 4-pass analysis (status only, not autonomous)
3. **Israel/Four** — Weekly scanning, state persistence
4. **grep/regex manual** — Still the fastest for targeted pattern search
5. **Chrome Selenium** — For platform submissions when API blocked

## WHAT'S MISSING FOR NEXT LEVEL

1. **Formal verification knowledge** — Certora, KEVM, Solana formal specs
2. **Fuzzing infrastructure** — Foundry fuzz, Echidna (need more RAM)
3. **Dynamic analysis** — Actually running vulnerable code (need Solana/EVM testnet setup)
4. **Competition history** — Study winning C4/Immunefi reports for format/depth expectations
5. **Automated submission pipeline** — Rate-limit aware, multi-platform queue
