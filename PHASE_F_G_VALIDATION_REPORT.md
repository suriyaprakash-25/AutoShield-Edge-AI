# AutoShield Edge AI — Phase F & Phase G Completion Report

**Validation date:** 2026-10-02
**Host:** Windows development laptop `SURIYAPRAKASH`
**Runtime:** Python 3.11.9, Node.js 22.21.0, npm 10.9.4
**Detector used by POC:** AutoShield Hybrid-v4 semantic parameter bundle

## Executive status

| Phase | Status | Result |
|---|---|---|
| Phase F — Demonstration simulator | **PASS** | All five scenarios produce deterministic, testable Hybrid-v4 outcomes |
| Phase G — Final validation | **PASS** | Python, frontend, browser, reconnection, launcher and documentation checks pass |

### Important scope statement

This report validates the **virtual Stage-2 POC**. It does not claim physical CAN/HIL or Raspberry Pi validation. RPM and Gear spoof evidence is produced by the frozen Hybrid-v4 Logistic Regression parameters; DoS/Fuzzy evidence is produced by the commissioned Hybrid-v4 deterministic policy.

## Phase F — Demonstration simulator

The simulator supports:
- Normal
- DoS
- Fuzzy
- RPM spoof
- Gear spoof
- Start
- Stop
- Reset
- deterministic replay after reset
### Scenario evidence audit

| Scenario | CAN ID | Hybrid-v4 evidence | Measured specialist result | Action | Status |
|---|---:|---|---|---|---|
| Normal | `0x130` | no evidence | n/a | `ALLOW` | PASS |
| DoS | `0x130` | `RATE_LIMIT_EXCEEDED` — 38 > 18 frames/100 ms | n/a | `RATE_LIMIT` | PASS |
| Fuzzy | `0x555` | `UNKNOWN_ID` — ID absent from commissioned allowlist | n/a | `DROP` | PASS |
| RPM spoof | `0x316` | `ML_RPM` | p=`0.981329` > th=`0.945376` | `ALERT` | PASS |
| Gear spoof | `0x43F` | `ML_GEAR` | p=`0.961983` > th=`0.931490` | `ALERT` | PASS |

RPM/Gear test samples intentionally remain within structural allowlist/rate/DLC policy, so their alerts cannot be explained by a simple unknown-ID or rate-rule shortcut.

### Repeatability

`test_start_stop_reset_repeatability` resets the simulator, reproduces the first RPM spoof frame/evidence, stops the engine, resets again and confirms identical frame + Hybrid-v4 evidence.

**Result: PASS**

## Phase G — Final validation

### Python integration suite

Command:

```powershell
python -m unittest discover -s tests -v
```

Result: **10 tests passed / 0 failed** in approximately **4.81 seconds**.
Covered tests:

1. Normal produces no alert and `ALLOW`.
2. DoS produces `RATE_LIMIT_EXCEEDED`.
3. Fuzzy produces `UNKNOWN_ID`.
4. RPM spoof crosses frozen RPM threshold.
5. Gear spoof crosses frozen Gear threshold.
6. Start/stop/reset is repeatable.
7. Full HTTP pipeline produces Gear ML evidence.
8. Backend process failure followed by restart returns to healthy state.
9. Mix / Combo interleaves DoS, Fuzzy, RPM spoof and Gear spoof and preserves all four Hybrid-v4 reason codes.
10. Full HTTP Mix / Combo pipeline exposes all four attack vectors.

### Frontend static analysis and build

```text
oxlint: 0 warnings, 0 errors
Vite: 590 modules transformed
dist/index.html: 0.48 kB
dist CSS: 2.27 kB
dist JS: 250.31 kB (78.95 kB gzip)
production build: PASS
```

### Dependency audit

An initial full npm audit identified two high-severity issues in transitive frontend tooling (`nanoid` and `postcss`). `npm audit fix` updated the affected packages.

Final audit:

```text
found 0 vulnerabilities
```
### Browser validation

Browser automation used the installed Google Chrome through Playwright.

Validated:

- dashboard loads from the production build
- backend status reaches `CONNECTED`
- Normal scenario stays at zero incidents
- DoS shows `RATE_LIMIT_EXCEEDED`
- Fuzzy shows `UNKNOWN_ID`
- RPM spoof shows `ML_RPM`
- Gear spoof shows `ML_GEAR`
- Mix / Combo shows `RATE_LIMIT_EXCEEDED`, `UNKNOWN_ID`, `ML_RPM`, and `ML_GEAR` in one interleaved run
- Mix / Combo renders a denser 30-packet CAN animation layer
- no unexpected page errors
- no unexpected console errors during normal operation
- backend is intentionally stopped
- UI changes to `RECONNECTING`
- backend is restarted
- UI returns to `CONNECTED`

Browser test output:

```text
BROWSER_CHECK_PASS
scenarios=normal,dos,fuzzy,rpm,gear,mix
reconnection=pass
console_validation=pass
can_animation=pass
mix_combo=pass
```

### Windows launcher

`run_autoshield.ps1` was tested both with an existing build and through the full build path.

Verified:
- dashboard build invoked successfully
- backend becomes healthy
- demo URL is reported
- demo scenario order is printed
- shutdown on Enter terminates the backend cleanly
### Model parameter integrity for local demo bundle

The local Windows demo JSON files are semantically equivalent copies of the audited Hybrid-v4 parameters, but were re-serialized and therefore are **not byte-identical B200 artifacts**.

Local demo SHA-256 values:

```text
00bed0b60db94f818b46274333ed8be62f45fd8efbe95ec8649b08c2d529fdcc  hybrid_policy.json
a5bebf21595f08218c607de53296d17d70155d672bcedee134484d034c4dee63  gear_specialist.json
330eff8a2e65ec0f650c93212827d6bb5c3bcd5ab9e3ffd355608a8f58a48805  rpm_specialist.json
```

## Two-minute demo procedure

1. **0:00–0:15 Normal** — Start, show clean traffic + 0 incidents, Stop, Reset.
2. **0:15–0:35 DoS** — Show rate evidence `38 > 18 frames/100ms`, action `RATE_LIMIT`, Stop, Reset.
3. **0:35–0:55 Fuzzy** — Show `UNKNOWN_ID`, action `DROP`, Stop, Reset.
4. **0:55–1:20 RPM spoof** — Show `ML_RPM`, probability above frozen threshold, action `ALERT`, Stop, Reset.
5. **1:20–1:45 Gear spoof** — Show `ML_GEAR`, probability above frozen threshold, action `ALERT`, Stop, Reset.
6. **1:45–2:00 Reliability** — Point to `CONNECTED`, mention automated stop/reset/reconnection tests, close with the edge-defense message.

## Final disposition

**Phase F: COMPLETE / PASS**

**Phase G: COMPLETE / PASS**

The build is ready for a repeatable Stage-2 **virtual POC demonstration**. Remaining physical-product work—Raspberry Pi 5 deployment, dual-CAN/SocketCAN integration and physical HIL enforcement—is explicitly outside this validation report and should be presented as the next hardware validation step.

## Packaged deliverable verification

A clean archive was created at `C:\Users\Suriy\Downloads\AutoShield_Stage2_PhaseFG_Validated.zip`.

The archive contains 103 project files, includes the validation report and Windows launcher, and excludes `.git`, `node_modules`, and `__pycache__`. A clean extraction was performed; all 10 Python tests passed again, dependencies installed with `npm ci`, frontend lint returned 0 warnings / 0 errors, and the Vite production build completed successfully.

## Live CAN visualization update

The vehicle cyber digital twin now includes a live SVG CAN-message animation layer.

Validation performed:

- Start renders animated packet markers on every displayed CAN path.
- Stop removes the moving packet markers immediately.
- Attack-highlighted paths inherit Hybrid-v4 node status colors.
- DoS increases packet density/speed to make bus loading visually obvious.
- A gateway heartbeat ring indicates active bus processing.
- The UI explicitly shows `LIVE CAN MESSAGE FLOW` while running and `CAN BUS PAUSED` while stopped.
- Browser automation now asserts that at least 10 animated CAN packet elements are present during Normal traffic and that none remain after Stop.

Browser result: **can_animation=pass**.

## Mix / Combo multi-vector mode

A new `Mix / Combo` scenario interleaves DoS, Fuzzy, RPM spoof, and Gear spoof attack vectors in a deterministic four-step cycle. Each vector is processed by the unchanged Hybrid-v4 detector, so the evidence log independently shows `RATE_LIMIT_EXCEEDED`, `UNKNOWN_ID`, `ML_RPM`, and `ML_GEAR` rather than a hard-coded generic mixed alert.

The digital twin keeps recent RPM and Gear targets highlighted, increases CAN animation density to 30 moving packet markers, and identifies each incident as `Mix · <attack type>`. Unit, HTTP integration, browser, animation, and launcher checks all pass for this mode.
