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

Result: **8 tests passed / 0 failed** in approximately **2.95 seconds**.
Covered tests:

1. Normal produces no alert and `ALLOW`.
2. DoS produces `RATE_LIMIT_EXCEEDED`.
3. Fuzzy produces `UNKNOWN_ID`.
4. RPM spoof crosses frozen RPM threshold.
5. Gear spoof crosses frozen Gear threshold.
6. Start/stop/reset is repeatable.
7. Full HTTP pipeline produces Gear ML evidence.
8. Backend process failure followed by restart returns to healthy state.

### Frontend static analysis and build

```text
oxlint: 0 warnings, 0 errors
Vite: 589 modules transformed
dist/index.html: 0.46 kB
dist CSS: 1.13 kB
dist JS: 241.79 kB (76.70 kB gzip)
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
- no unexpected page errors
- no unexpected console errors during normal operation
- backend is intentionally stopped
- UI changes to `RECONNECTING`
- backend is restarted
- UI returns to `CONNECTED`

Browser test output:

```text
BROWSER_CHECK_PASS
scenarios=normal,dos,fuzzy,rpm,gear
reconnection=pass
console_validation=pass
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

The archive contains 66 project entries, includes the validation report and Windows launcher, and excludes `node_modules`. A clean extraction was performed; all 8 Python tests passed again, dependencies installed with `npm ci`, and the Vite production build completed successfully.
