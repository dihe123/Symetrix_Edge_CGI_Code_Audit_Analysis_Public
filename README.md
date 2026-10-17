# Symetrix Edge Audio DSP — Binary Code Audit Analysis of the CGI Components

> **About this public version**
> This document records the process, methodology, and conclusions of a **binary code audit** performed against the Web management interface (lighttpd + CGI) of an embedded device.
> The body text is **detailed down to audit phases, call sites, frame layouts, and root causes**, but **deliberately blurs every actionable detail**: it contains no runnable payload, no copy-pasteable request, no overflow trigger threshold, and no exploit-material construction.
> Readers can use it to understand *why the problems arise, how the audit located them, and how they should be fixed*; the operational information needed to actually verify against an in-field device is not provided here.

---

## 0. Disclosure Status

| Item | Content |
|---|---|
|HUANGQIXIN|
| First discovery | 2026-10 |
| Target | CGI components of the Symetrix Edge family of audio DSPs |
| Coordination status | Submitted to CNVD; coordination with the vendor in progress |
| Disclosure policy | This document is a **low-operational-detail technical analysis**; full reproduction material is withheld until the vendor ships a fix |

> If the vendor releases a fix or agrees to disclosure, the timeline in §10 will be updated with the fixed version and acknowledgements. Until then, do not use this document to run verification against in-field devices.

---

## 1. Summary

Symetrix Edge is an audio DSP built on the ADI ADSP-SC589. Its Web management surface is served by `lighttpd/1.4.55`, with business logic implemented by several CGI executables. This round of **purely static auditing** (Ghidra decompilation + DWARF symbols + disassembly cross-validation) distilled **12 findings** across the three CGI binaries (2 of which are informational and excluded from the impact surface), spanning five attack surfaces:

| Attack surface | Nature |
|---|---|
| Authentication | Client self-attests its own authenticated state → auth bypass; which in turn spawns a global-buffer overrun |
| Command execution | Parameters concatenated into a shell string, with an incomplete escaping allow-list |
| Memory corruption | Stack buffer overflow, global buffer overflow, unbounded decode write |
| Format string | External data (upstream DSP reply / device configuration) used as a format string |
| Information disclosure | Cleartext credentials written to logs, unsalted password digest |

This document is organized by the **audit viewpoint** rather than the **ID viewpoint**: first *how many phases the audit has and how each is done* (§3), then *what was found on each surface and on what grounds the conclusion rests* (§4), and finally the **common root causes** (§6), **comparable CVE references** (§7), and **remediation direction** (§8).

---

## 2. Target and Scope

### 2.1 Analyzed Artifacts

| Component | Size | SHA-256 |
|---|---|---|
| `arc_mix_cgi` | 216741 B | `16e40cdbb2aa27d31b6ca91167213d77b7479ee6aa80952d342ffe0310148663` |
| `arc_web_cgi` | 69467 B | `570be7f1aca3d58f03de11d17a0c9fde3d9e74b386461b68b3906d8e203a63b4` |
| `dialer_cgi` | 191667 B | `8eed0fcaa7b923c08434358e5663f72b8a570e9458c99472901e4a38aad86fce` |

All three were taken from the device's `/cgi-bin/` directory (the `lighttpd/1.4.55` directory listing).

### 2.2 Runtime Environment

| Dimension | Value |
|---|---|
| Architecture / ABI | ELF 32-bit LSB **ARM, EABI5** (`arc_web_cgi` is **Thumb**; the other two are ARM mode) |
| SoC | ADI ADSP-SC589 |
| OS | Linux 3.16.0 |
| Web server | lighttpd/1.4.55 (CGI) |
| Toolchain | ADI CCES Linux Add-In 1.2.0 / GCC 4.8.3 `-g -O2` |
| Build path | `/home/jharris/workspace/Edge_Firmware/...`, **shared module `edge_common`** |

### 2.3 Binary Properties and Mitigations (Key Premise)

| Property | `arc_mix_cgi` | `arc_web_cgi` | `dialer_cgi` |
|---|---|---|---|
| Architecture mode | ARM 32-bit EABI5 | ARM 32-bit (**Thumb**) | ARM 32-bit |
| Symbols / debug info | **Not stripped (DWARF present)** | same | same |
| PIE / ASLR | **Non-PIE** | Non-PIE | Non-PIE |
| Stack Canary | **None** | None | None |
| NX | On | On | On |
| RELRO | **None (GOT writable)** | None | None |
| `system` / `popen` / `exec*` | `system` ×3 | none | none |

**Addressing**: all three are **non-PIE**, so `vaddr = file offset + 0x8000`; capstone disassembly addresses line up 1:1 with Ghidra addresses.

> Audit experience: the first thing to check on any firmware is the **mitigation trio** (Canary / PIE / RELRO). Here all three are absent, which means the **ceiling** for memory-class flaws is not "crash" but "writable, hijackable" — this directly sets the severity rubric used later in §4.

### 2.4 Common Request Model

lighttpd invokes these as CGI: input is drawn from the environment variables **`QUERY_STRING`** (`name=value` separated by `&`/`=`) and **`HTTP_COOKIE`**; output is a `Set-Cookie` plus JSON text.

> **Audit pitfall (recording one early misjudgement)**: the initial approach looked for an entry point in `argv`, following the classic CGI mental model, and static back-tracing led nowhere. Corrected to "the query string is read from `getenv("QUERY_STRING")`", and further confirmed that `arc_mix_cgi`'s dispatch key is `data=` (values `create_dir` / `move` / `delete` …), not `file=`. **Getting the entry parameter exactly right is the foundation for every downstream data-flow trace.**

### 2.5 Vendor Information

| Item | Content |
|---|---|
| Vendor | Symetrix, Inc. (Washington State, USA) |
| Website | https://www.symetrix.co/ |
| Edge product page | https://www.symetrix.co/products/edge/ |
| Product knowledge base / FAQ | https://www.symetrixinc.com/knowledge/faq-edge-dsp/ |
| Vendor address | 6408 216th Street SW, Mountlake Terrace, WA 98043, USA |

> For vulnerability coordination, please route via the support channel published on the vendor's website to reach their security team; this document does not publish a security contact on the vendor's behalf.

---

## 3. Audit Phases (Detailed)

### 3.0 Phase Overview

The audit proceeds through six phases — **reconnaissance → mapping → localization → corroboration → review → severity** — where each phase's output feeds the next:

```
[Phase 1 Recon]      properties / mitigations / symbols / addressing  -> outputs: whether symbols are trustworthy, address convention
      |
[Phase 2 Mapping]    entry model / dispatch keys / dangerous sinks     -> outputs: attack-surface list + sink list
      |
[Phase 3 Localize]   DWARF frame layout / data flow / trust boundaries -> outputs: candidate bugs and their "why"
      |
[Phase 4 Corroborate] qemu-user + device stand-ins + gdb value-driven  -> outputs: measured facts (nails the conclusion)
      |
[Phase 5 Review]     pseudocode does not count / DWARF+disasm agree    -> outputs: false positives removed
      |
[Phase 6 Severity]   item-by-item CVSS recomputation + grouping        -> outputs: ratings and priorities
```

### 3.1 Phase 1 — Binary Reconnaissance

**Goal**: without powering on a device, first establish "what can be trusted, and how addresses are computed".

1. `strings` / `readelf`: confirm **not stripped and carrying DWARF** (here including source file names `edge_common.cpp`, `WideChar.cpp`), which amounts to obtaining half a source map.
2. Identify the compiler and build path (GCC 4.8.3, `Edge_Firmware`) — to gauge the code's era and likely coding habits (e.g. whether C++ `std::string` is used, whether shell commands are hand-assembled).
3. Confirm the **address convention**: non-PIE ⇒ file offset + fixed base (here `+0x8000`); only once disassembler and decompiler addresses are aligned can their conclusions corroborate each other.
4. Record the **mitigation trio** and the presence of the `system` family (`arc_mix_cgi` shows `system` ×3, a **prior signal** for command injection).

### 3.2 Phase 2 — Attack-Surface and Dangerous-Sink Mapping

**Goal**: draw clearly "who can get in, and where it goes once inside".

1. **Entry mapping**: confirm the input surface is only the `getenv` family; parse the `QUERY_STRING` dispatch function to obtain the **dispatch-key → business-function** mapping (see the correction in §2.4).
2. **Dangerous-sink inventory**, with source traced back per class:

| Sink class | Concrete calls | Audit focus |
|---|---|---|
| Command execution | `system` / `popen` | whether parameters reach the shell, whether escaping is complete |
| Formatted output | `printf` / `sprintf` / `fprintf` | **whether the first argument is controllable** |
| Unbounded copy | `sprintf` / hand-written decode loops | whether the destination is fixed-size, whether the source length is externally controllable |
| Config / log output | `fprintf(stderr, …)` | whether sensitive data is included |

3. **Upstream-dependency identification**: CGI and DSP communicate over a **custom UDP frame protocol** (with a `magic + cmd + size` structure). Anywhere "reply content enters this process's buffer" is registered as a **potential external input** — the foreshadowing for the §4.4 format strings.

### 3.3 Phase 3 — Static Localization and Data-Flow Tracing

**Goal**: for each sink, answer "how do user-controllable bytes arrive".

1. **Primary data-flow chain**: `getenv("QUERY_STRING") → parse/URL-decode → parameter binding → business function → sink`.
2. **DWARF frame layout**: for suspicious functions, take the local variables' **negative CFA offsets** and **true buffer sizes**. This is the only reliable basis for "how far it is to the return address" (the decompiler's pseudocode **does not count** here).
3. **xref attribution**: from PLT stub → GOT slot → import name, determine which libc function each `bl` lands on (independent of import order), avoiding mistaking `sprintf` for `strcpy` and the like.
4. **Trust-boundary tagging**: mark all three sources — "HTTP input", "upstream DSP reply", "device configuration file" — as **untrusted sources**, rather than trusting on-device data by default.

**Three key threads in this phase**:

- **Thread A (authentication)**: all three CGIs call the same auth function `IsUserAuthenticated`, which internally uses `sprintf` to build the Cookie name — two birds with one stone: examine the authentication logic and examine that `sprintf`'s destination size.
- **Thread B (length → fixed-size buffer)**: register every "external length → fixed-size buffer" write site, and hand-compute each one's "overflow start point / distance to the saved register".
- **Thread C (format string)**: for all `printf`-family calls, check **whether the first argument is a literal constant or external data**.

### 3.4 Phase 4 — Dynamic Corroboration (Without a Device)

Static analysis yields only "possible"; dynamic validation is needed for "actual". To corroborate **without touching a real device**:

1. **qemu-user + armhf sysroot**: run **the very same binary** directly (non-PIE ⇒ addresses match the device bit-for-bit).
2. **Device stand-ins**:
   - replicate the **environment-variable contract** lighttpd passes to the CGI (`QUERY_STRING` / `HTTP_COOKIE` / `REQUEST_METHOD` / `CONTENT_LENGTH`);
   - **configuration-file seeding** (write known fields at predetermined offsets, emulating the real configuration);
   - **DSP loopback UDP stub** (replying under the same frame protocol), turning "upstream controllable" from an assumption into a **controlled variable**.
3. **gdb value-driven observation**: break at the sink and read the arguments, the buffer, and the saved-LR slot — concluding from **values**, not impressions.

> This phase best illustrates the value of corroboration: for two things both called "out-of-bounds write", whether the **write endpoint reaches the return address** swings the conclusion between "DoS" and "RCE". Of the two out-of-bounds writes in §4, one does not reach the return address (rated DoS) and one reaches control flow (rated High) — **the difference can only be settled by measurement**.

### 3.5 Phase 5 — Review and False-Positive Elimination

**Core rule**: **the decompiler's pseudocode is not a basis for conclusions**; a finding is only asserted when **DWARF offsets and instruction-level disassembly truth agree**. Review method: take negative CFA offsets and true buffer sizes from `<bin>.dwarf.json`, take instruction-level truth from `disasm.py`, and check they agree.

Typical false positives eliminated on this basis:

| Symptom | Review conclusion |
|---|---|
| `sscanf(dst,fmt)` decompilation "loses the destination pointer" | Ghidra variadic artifact; the destination is passed in a register → not a bug |
| Several `memcpy` in `foreReceive` look out of bounds | DWARF shows the destination **aliases** a local buffer, all writes stay within the frame → false positive |
| "`int nIndex` used as a large buffer" | In DWARF it aliases the real large buffer, capacity sufficient → false positive |
| `foreAddStringResponse` length-prefixed `memcpy` | Executes only for loopback sources → internal trust, not externally reachable |
| `UrlDecodeText` destinations in various `DoLongPoll` paths | Source truncated to fixed length + NUL → within frame → false positive |
| Literal `DAT_xxxx` used as a number | Actually a literal-pool slot address → false positive |

> This step is the source of an audit report's credibility: **an audit without false-positive elimination treats noise as findings**.

### 3.6 Phase 6 — Severity and Grouping

1. **Item-by-item CVSS v3.1 Base recomputation** (`Expl=8.22·AV·AC·PR·UI`; `ISS=1-(1-C)(1-I)(1-A)`; `S:U→Impact=6.42·ISS`; `Base=roundup(min(Impact+Expl,10))`), not scored by impression.
2. **Reachability preconditions** tagged per item (whether authentication is required, whether an upstream reply is required, whether the configuration is writable).
3. **Grouping by component**: if a single root cause exists in two independent binaries and their **reachability preconditions differ**, handle them as two items (see the global overflow in §4.3).

### 3.7 Toolchain

- Ghidra 11.3.2 + GhidraMCP (HTTP; batch decompilation, cross-references).
- Custom scripts (capstone + pyelftools): `dwarf_dump.py` (structures/functions/locals → `*.dwarf.json`), `xrefs.py` (PLT→GOT→import-name attribution), `disasm.py` (disassemble a given vaddr).

---

## 4. Audit Findings (Condensed)

> The numbering below follows the underlying audit report (V1–V12, including 2 informational items); for CVE submission they are regrouped by component. All addresses are `vaddr` (file offset + `0x8000`).

### 4.0 Summary

| ID | Component | Type | Location (vaddr) | Auth precondition | CVSS | Tier |
|---|---|---|---|---|---|---|
| V1 | arc_mix_cgi | Command injection (`system`) | `DoCreateDir 0xc408` / `DoMove 0xcb54` / `DoDelete 0xc77c` | Post-auth (or security off) = effectively unauthenticated | 9.8 | Critical |
| V2 | arc_mix_cgi | Stack buffer overflow (saved LR) | `IsUserAuthenticated+0x40` `0xa400` | **Unauthenticated** (triggers when security is on) | 7.5 / 8.1 | High |
| V3 | all three | Auth bypass (unsigned Cookie) | `IsUserAuthenticated` (each binary) | Unauthenticated | 9.8 | Critical |
| V4 | arc_web / dialer | Global buffer overflow (`.bss`) | `IsUserAuthenticated` (arc_web `0x9874` / dialer `0x9f7c`) | Unauthenticated (arc_web additionally needs a DSP constraint; dialer directly reachable) | 9.1 | High |
| V5 | dialer_cgi | Unbounded write (in-frame / DoS) | `UrlDecodeText 0xb48c` | Post-auth (bypassable via V3) | 7.5 | High |
| V6 | arc_web_cgi | Format string | `print_main_menu 0x97a4` | Unauthenticated | 7.5 | High |
| V7 | dialer_cgi | Format string | `print_dialed_strings 0xbd30` | Post-auth | 7.5 | High |
| V8 | dialer_cgi | Config-derived format string | `GetDisplayValue 0xe75c` ← `DoVolumeUpDown 0xb75c` | Post-auth + writable config | 6.6 | Medium |
| V9 | arc_mix / dialer | Cleartext credentials in logs | `GetCredentials` (arc_mix `0xf918` / dialer `0xe5f0`) | Local | 5.5 | Medium |
| V10 | dialer_cgi | Unsalted MD5 + `strcmp` timing | `ValidateUser 0x9da4` | Requires obtaining the digest first | 5.9 | Medium |
| V11 | arc_mix_cgi | Input filter is dead code | `ValidateFilename 0xadf8` | — | N/A | Info |
| V12 | dialer_cgi | UDP IPC bound to `INADDR_ANY` + `SO_BROADCAST` | `osipBindSocket 0xd9cc` | Same subnet | 5.4 | Medium (informational) |

---

### 4.1 Authentication Surface

#### V3 — Root Cause of the Auth Bypass

**Path**: each of the three CGIs implements `IsUserAuthenticated` (arc_mix `0xa400` / arc_web `0x9874` / dialer `0x9f7c`).

**Mechanism**: the Cookie name is `sprintf(buf, "%s_auth", <instance|file>)`, and its value is a timestamp; a companion `<name>_timeout` (in minutes) goes with it. The check reads `_auth` (only requires parsing out a timestamp) and `_timeout` (converted to seconds), then performs a **time-window test**; if the window condition is not satisfied, it does not `return false`, ultimately falling through to `return true`.

**Two audit judgements**:
1. **Client self-attestation**: the Cookie has **no signature, no HMAC, no server-side session** — the client can construct one that passes.
2. **Boolean short-circuit**: given that `_auth` **exists**, setting `_timeout` to 0 makes the left term of the window condition false, the `&&` short-circuits to false, `return false` is not reached, and thus it "legitimately" passes. Note the `_auth` existence check comes first — sending only `_timeout` is first rejected as "no auth Cookie".

**Classification**: CWE-565 / CWE-290. This is **the amplifier for the entire attack surface** — it throws open every path that would otherwise be "reachable only after authentication", and is therefore singled out at the highest priority.

#### V2 — Stack Overflow in the Auth Function (arc_mix)

**Path**: `IsUserAuthenticated` @ `0xa400` (sole call site `0x9964`), argument = the global `g_instance` (`0x1cd28`, `char[64]`, filled from `instance=` via `strncpy(...,0x40)`).

**Evidence (DWARF + disassembly agree)**:
- DWARF: local `cookieName` typed **`char[20]`**, CFA offset **-52**;
- Disassembly: `push {r4,r5,r6,r7,r8,sb,lr}` + `sub sp,#0x24`; the buffer is at `sp+0xc`; `add r0,sp,#0xc` followed by `bl sprintf`;
- Call: `sprintf(cookieName, "%s_auth", pInstance)` (`0xa43c`).

**Root cause**: the written length is `len(pInstance)+5`, against a 20-byte fixed destination. The saved `LR` sits at CFA-4, i.e. **48 bytes** away from the buffer. **Exceeding the buffer size immediately begins overwriting adjacent saved registers**, without waiting for the saved LR.

**Reachability (unauthenticated)**: `main` first takes `IsSecurityEnabled()`, and **when security is enabled (returns 1) it unconditionally calls `IsUserAuthenticated(g_instance)`, before any authentication result is decided**. That is: **a hardened configuration (security ON) actually opens this unauthenticated corruption point**.

**Classification**: CWE-121. With no Canary / non-PIE / only NX, this constitutes a **control-flow hijack risk** (the payload is constrained by "address high byte is 0x00" so a full address is hard to embed directly, but **partially overwriting the low bytes of the return address** is a realistic and strong primitive).

---

### 4.2 Command Execution Surface

#### V1 — arc_mix_cgi Command Injection

> **CVE description (draft)**: arc_mix_cgi in Symetrix Edge Audio DSP 3.16.0 contains a command injection vulnerability in DoCreateDir (0xc408) due to incomplete escaping of the name parameter before passing it to system().

**Path**: `DoCreateDir 0xc408` (assembly loop `0xc570`/`0xc5f0`), `DoMove 0xcb54`, `DoDelete 0xc77c`; dispatched by `data=create_dir` / `move` / `delete`.

**Evidence**:
- The command template (string table) is of the form `mkdir -p "/home/composer/media/<name>"`;
- The assembly loop processes the input **character by character**, but the **escaping allow-list is incomplete**: it only prefixes a backslash to double quotes and backticks, **leaving the other shell metacharacters unhandled**. And **within a double-quoted word**, several shell expansion constructs **still take effect**;
- Finally `bl 0xac14` → the `system` path (PLT `0x8f94 = system`).

**Why this is a classic audit blind spot**: the developer did escape things, so it "looks safe"; but the **escape set is incomplete**, and it ignores the shell semantics that "expansion still occurs inside double quotes". For command-concatenation issues, **the key question is not "is there escaping" but "does the escape set cover all metacharacters in that shell context"**.

**Classification**: CWE-78, arbitrary command execution with the CGI process's privileges → RCE. The auth precondition is bypassable via V3, i.e. effectively unauthenticated; dispatch additionally requires `instance=mm` (`g_mixInstIdx != -1`).

**Related**: the codebase **contains** a filename-filter function `ValidateFilename`, but it is never called (see §4.6 V11) — protection "written but never wired up".

---

### 4.3 Memory Corruption Surface

#### V4 — Global Buffer Overflow (arc_web / dialer)

**Path**: `IsUserAuthenticated` (arc_web `0x9874` / dialer `0x9f7c`), whose argument is the global `g_file` (arc_web `0x131f8`, `char[768]`; dialer `0x294a4`, `char[64]`); the destination is the **global** `cookieName` sharing the same origin as §4.1 (arc_web `0x134f8` / dialer `0x294ec`, both `char[20]`).

**Root cause**: the same statement `sprintf(cookieName, "%s_auth", g_file)`, but this time `cookieName` lands in the **`.bss` global region** rather than the stack — the overrun overwrites adjacent global objects (parameter buffers, socket handles, etc.), so its nature is **global data corruption** rather than stack hijacking.

**One root cause, two components, two reachabilities** (precisely why they are handled as two items):
- **dialer**: no extra precondition, **directly reachable**;
- **arc_web**: must first pass `MatchUrl(g_file)` (`0x9548`, which sends the URL to the local DSP via `send_command(0x2008)` and takes a 1-byte reply), i.e. `file=` must be a URL the DSP recognizes and exceed a certain length — **that constraint depends on the device side and cannot be enumerated purely statically**.

**Classification**: CWE-121. A `file=` far longer than 20 bytes suffices as input for the out-of-bounds write; no direct function-pointer overwrite path was found, so it is rated High rather than Critical.

#### V5 — dialer_cgi Unbounded Decode Write

**Path**: `UrlDecodeText 0xb48c`, called from `main`'s `set_string` / `direct_dial` paths.

**Root cause**: the function **bounds only the source length, not the destination length** — the source goes through `strnlen(src, 0x400)` (cap 1024 B), while the destination is a 256-byte local buffer (DWARF: `decodedVal` offset `-1488`, `char[256]`). The write loop **has no destination bounds check**.

**Why corroboration matters**: measuring the write endpoint with gdb confirmed it has **roughly 460 B of margin before the saved-LR** — i.e. the current form is **deterministic memory corruption / DoS**, **not** direct RCE. **Two "out-of-bounds writes" of the same kind get different ratings because their write endpoints differ — only measurement settles it**.

**Contrast**: another call of the same function (`nIndex`, a 1200-byte buffer) is **safe** — showing the problem lies in "the call site chose too small a buffer", not that the function itself is "necessarily wrong".

**Classification**: CWE-787.

---

### 4.4 Format String Surface

#### V6 / V7 — Upstream Replies Treated as Format Strings

**V6**: `arc_web_cgi::print_main_menu 0x97a4` — `printf(out_str)`, where `out_str[1500]` is filled by `send_command(0x2001, …)` from the **local DSP** (loopback UDP); **there is no format constant**.
**V7**: `dialer_cgi::print_dialed_strings 0xbd30` — after `sprintf(output, "…%d…%s…", …)`, a **`printf(output)`**, where the string segment comes from a device-side string value.

**Audit judgement**: both are "**external data used as the format string**". The trigger is the **upstream DSP reply**, which requires the ability to write that reply on the device side — an external attacker cannot reach it alone, so both are rated at the **AV:A/AC:H** tier (forged reply on an adjacent subnet).

#### V8 — Config-Derived Format String

**V8**: `dialer_cgi::GetDisplayValue 0xe75c`, receiving buffer `displayText[33]` (DWARF offset `-76`), located in `DoVolumeUpDown 0xb75c`.
**Root cause**: `sprintf(pDisplayText, (pMenu->desc).cnt.formatString, <double>)` — the **format string is taken from the device configuration** (a menu description field). If the configuration can be polluted so that this field contains a length directive, it causes an out-of-bounds write into the 33-byte stack buffer.

**Verification approach (the criterion used here)**: parameterize the "reply/config content" — let the stub reply with different content and write different fields into the configuration, then observe whether the **literal marker and the format specifier in the output change in lockstep**. If the expansion of the format specifier changes with the external content, the format string can be concluded to be 100% from that external source, ruling out coincidence.

**Classification**: CWE-134. Impact is tiered by controllability: upstream reply controllable → medium-high; configuration controllable → medium (requires config write permission).

> The lesson of this class: **"same machine / same subnet" does not equal "trusted"**. If a CGI↔DSP UDP channel can be forged, the DSP reply must be treated as untrusted input.

---

### 4.5 Information Disclosure Surface

#### V9 — Cleartext Credentials in Logs

**Path**: arc_mix `GetCredentials 0xf918`, dialer `GetCredentials 0xe5f0` / `GetUsernamePassword 0xe520`; `IsUserAuthenticated` also has an `fprintf(stderr, …)` for the Cookie name. (**`arc_web_cgi` has neither this format string nor `GetCredentials`, so it does not apply.**)
**Evidence**: after assembly, credentials are emitted via `fprintf(stderr, …)` — **cleartext username + password to standard error**, printed on a normal startup.
**Classification**: CWE-312 / CWE-532. Readable from local or logs ⇒ disclosed.

#### V10 — Unsalted Password Digest

**Path**: dialer `ValidateUser 0x9da4` (local `char data[62]`).
**Evidence**: **unsalted MD5**, with the digest compared via `strcmp` — carrying both an **offline rainbow-table** risk and a `strcmp` **timing side channel**.
**Classification**: CWE-916 / CWE-759. Combined with V9, it forms a "log → digest → recover password" acquisition chain.

---

### 4.6 Surfaces Examined but Not Included

- **V11 `ValidateFilename` dead code** (`0xadf8`): no reachable call to `0xadf8` anywhere in `.text`; its blocklist string is referenced only by the function itself, which in practice blocks only `../` variants. **The filename filter that was designed never executes** — echoing V1 directly (protection written but not wired in). Classified as **informational**, not listed as an impact.
- **V12 UDP IPC exposure** (`osipBindSocket 0xd9cc`): bound to `INADDR_ANY` with `SO_BROADCAST` set, so the IPC can send/receive across the entire subnet. This is an **attack-surface reduction recommendation**; this analysis does not list it as an impact.

---

## 5. Exploit Chains (Concept-Level, Blurred)

Only the **relationships between stages** are given, with no actionable material whatsoever. The first step of every chain is usually the auth bypass in §4.1.

```
[Auth bypass] ──┬─→ [Command injection] ───────────→ Remote command execution (RCE)
                │
                ├─→ [Global buffer overflow] ──────→ Global data corruption (may disturb parameter buffers/handles)
                │
                └─→ [Stack buffer overflow] ───────→ Memory corruption / potential control-flow hijack

[Upstream DSP reply controllable] ──→ [Format string] ──→ Memory read (stack/register leak) ─┐
                                                                                             ├─→ Arbitrary write → combine with the above
[Config field controllable]       ──→ [Format string] ──→ Memory read / write ───────────────┘

[Cleartext credentials in logs] ──┐
                                  ├─→ Credential acquisition → auth material / offline recovery
[Unsalted password digest]      ──┘
```

Key points:

1. **Auth bypass is the "surface opener"**: it pulls several "post-auth-only" flaws from the theoretical surface to the practical surface, hence listed highest on its own.
2. **Memory-class flaws share one premise** (no Canary / non-PIE / no RELRO), which sets their **ceiling** rather than "whether they crash".
3. **Format strings are a "read→write" bridge**: first leak layout with the read primitive, then land the write primitive — a typical two-stage pattern.
4. **Information disclosure forms an independent chain** on its own: it need not rely on memory corruption and can advance to the credential layer via logs/digest alone.

> There remains an appreciable distance from "finding" to "usable exploit" (payload constraints, address constraints, upstream-controllability assumptions); this document **deliberately stops here** and does not reproduce that distance.

---

## 6. Common Root Cause Summary

| Pattern | Symptom | Essence |
|---|---|---|
| Client self-attestation | Cookie present ⇒ passes | Missing server-side integrity check |
| Incomplete escaping allow-list | Escapes present but misses metacharacters | Confusing "escaping" with "a safe shell context" |
| External length → fixed-size buffer | `sprintf` / hand-written copy with no bounds check | Not treating "external length" as untrusted |
| External content as format string | `printf(x)` / `sprintf(d, x, …)` | Mixing data with format |
| Upstream treated as trusted | DSP reply used directly | Trust boundary drawn incorrectly |
| Protection not wired in | Filter function exists but is never called | A defense was written but not enabled |
| Sensitive data in logs | Cleartext password / weak digest | Missing logging policy |

> In one sentence: **"trusted the wrong source, computed the wrong length, mixed up the semantics, wired up an empty defense"** — corresponding respectively to trust boundary, bounds checking, data/format confusion, and protection failure. These four error classes are highly reusable across embedded Web management surfaces and merit self-inspection by similar products.

---

## 7. Comparable CVE References and Similar Techniques

The flaws found here are not isolated — they are **patterns that recur on embedded-device Web management surfaces**. The table below lists publicly disclosed **comparable CVEs** (same defect class, similar trigger technique) for cross-reference, severity corroboration, and root-cause confirmation.

| Reference CVE | Product / component | Defect class | Similar technique | Mapped to |
|---|---|---|---|---|
| **CVE-2021-36260** (9.8, CISA KEV) | Hikvision IP camera / NVR Web service | Unauthenticated command injection CWE-78 | Insufficient Web input validation → parameter concatenated into a command | V1 |
| **CVE-2025-60687** | TOTOLINK LR1200GB `cstecgi.cgi` | Unauthenticated command injection CWE-78 | Parameter concatenated into `system` via `sprintf` | V1 |
| **CVE-2021-27561 / 27562** (9.8, KEV) | Yealink device management platform | Pre-auth SSRF + command injection CWE-78 | Unauthenticated, a single HTTPS request fires a root command | V1 + V3 chain |
| **CVE-2026-73673** | Netis NC63 (Boa + `netis.cgi`) | Missing authentication CWE-306 | CGI **reads but does not enforce** cookie / session | V3 |
| **TOTOLINK A800R** | `cstecgi.cgi` + lighttpd | Missing authentication CWE-306 | lighttpd does not enforce auth on CGI POST | V3 |
| **WAGO 852-1322 / 852-1328** | Modified lighttpd + custom CGI | Auth bypass + cookie-parsing stack overflow | Path traversal bypasses auth + **oversized cookie triggers stack overflow** | V3 + V2/V4 |
| **CVE-2026-76071** | Netis NC63 `netis.cgi` | Stack buffer overflow CWE-121 | Width-less `sscanf` conversion → **pre-auth** RCE (root) | V2 |
| **CVE-2026-7248** | D-Link DI-8100 `tgfile_htm` | Stack buffer overflow CWE-121 | `sprintf` fixed prefix + user parameter with no length check | V2 / V4 |
| **CVE-2026-57877** | GeoVision `vlsvr` (login path) | Format string CWE-134 | Unauthenticated, external input into printf-style log formatting | V6 / V7 |
| **CVE-2026-3509** (7.5) | CODESYS Control runtime | Format string CWE-134 | Unauthenticated control of a log format string → DoS | V8 |

**Common observations**:

1. **Highly stable patterns**: the four classes — `unauthenticated web command injection`, `cookie/session not enforced by the CGI`, `cookie- or parameter-triggered stack/global overflow`, `external input as format string` — **recur** across router, camera, access-control, and controller Web surfaces, and most are triggerable **without authentication** — consistent with the basic picture here.
2. **KEV corroborates severity**: CVE-2021-36260 and CVE-2021-27561/27562 both entered **CISA KEV** (known exploited) and were weaponized by Mirai/Moobot-lineage botnets. This indirectly confirms that **the combination of "unauthenticated + web-facing + no canary/non-PIE" genuinely gets exploited at scale in the wild**, consistent with rating V1 / V3 Critical here.
3. **Similar chained structures**: Yealink (SSRF→command injection) and WAGO (auth bypass→overflow) both confirm the "**bypass auth first, then trigger a memory/command-class flaw**" chained approach, cross-referencing the structure of the exploit chain in §5.

> Note: the table above consists of **publicly disclosed comparable cases**, for cross-reference only, and **does not imply that this product is affected**; for details of each, refer to the corresponding official CVE records.

---

## 8. Remediation Recommendations

Ordered by priority and return on investment:

1. **Rework the authentication mechanism** (highest): make the authenticated state **server-verifiable** (signature / server-side session); Cookie names must not be derived by concatenating request parameters; fix the time-window boundary logic (cases outside the window must be **explicitly judged invalid**, never falling through to default-pass).
2. **Eliminate command concatenation**: replace the `system` string with an `execve` argument array; where a shell is unavoidable, validate each argument against an allow-list rather than "listing a pile of characters to escape". **Also wire in the existing filename filter** (V11).
3. **Normalize formatted output**: the **first argument of every `printf/sprintf` must be a literal constant**, with external data only as the **argument** to `%s` — the same applies to data from the DSP and configuration files.
4. **Close the bounds-checking gaps**: change every "external length → fixed-size buffer" write site to `snprintf` / a copy carrying `dst_size`; add a destination-length parameter to decode-class functions.
5. **Enable compile-time mitigations**: turn on Stack Canary and PIE (all three are currently absent on this platform; cost is manageable, benefit significant), and consider RELRO.
6. **Sensitive data governance**: remove/downgrade debug prints, and redact when logging is genuinely needed; move password storage to a salted slow hash (PBKDF2 / Argon2), comparing with a constant-time function.
7. **Tighten trust boundaries**: treat the CGI↔DSP UDP channel as untrusted input, validating the length and content of replies; restrict the UDP IPC bind to loopback or a specific interface.

---

## 9. Reproduction Environment Notes (No PoC)

To help peers assess the credibility of the conclusions, here is how they were obtained **without a real device**:

- **The same binary**: the dynamic validation ran the executable downloaded from the device (sha256 aligned with the device directory-listing size).
- **Architecture alignment**: `qemu-user` emulates ARM EABI5 userland; being **non-PIE**, function addresses match the device bit-for-bit.
- **Input-contract alignment**: the same environment variables replicate lighttpd's CGI invocation contract.
- **Controlled upstream dependency**: the DSP loopback UDP stub replies under the same frame protocol, turning "upstream controllable" into an explicit assumption.
- **Observation method**: gdb is used to **read values** (buffer, saved-LR slot, arguments), **without constructing an exploit**.

> The resulting **address-level and behavior-level** conclusions transfer to the same binary in the device firmware. **This document contains no trigger request/payload/threshold**; if the vendor needs reproduction material, it can be provided through coordination channels.

---

## 10. Timeline

| Date | Event |
|---|---|
| 2026-10 | Completed static audit and mapping of the three components |
| 2026-10 | Built the device-free reproduction environment (qemu-user + device stand-ins), corroborating each item dynamically |
| 2026-10 | Prepared the report, submitted to CNVD |
| To be updated | Coordination with the vendor in progress; fixed version and acknowledgements will be updated here |

---

## 11. Disclaimer

This document is intended solely for **security research and vulnerability remediation**; the analysis and recommendations it contains are directed at devices and products that are **owned by the reader or covered by written authorization**. Do not use the information here against any unauthorized target; do not use this analysis to run verification against in-field devices before the vendor releases a fix.

---

*This is the public version, which deliberately omits actionable details (payloads, requests, trigger thresholds, exploit material). For technical exchange and vendor coordination, please use the proper disclosure channels.*
