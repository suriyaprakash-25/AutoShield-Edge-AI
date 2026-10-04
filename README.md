# AutoShield Edge AI — Stage-2 Virtual POC

AutoShield is a gateway-oriented CAN cybersecurity POC. This Stage-2 build demonstrates the **frozen Hybrid-v4 decision logic** in a repeatable simulator and browser dashboard.

## What this build proves

- Six repeatable scenarios: Normal, DoS, Fuzzy, RPM spoof, Gear spoof, and Mix / Combo.
- Every attack is evaluated by Hybrid-v4 evidence, not a dashboard-only animation.
- DoS is evidenced by the commissioned per-ID rate policy.
- Fuzzy injection is evidenced by the CAN-ID allowlist.
- RPM spoof uses the frozen `0x316` Logistic Regression specialist.
- Gear spoof uses the frozen `0x43F` Logistic Regression specialist.
- Start, stop, reset and scenario switching are deterministic.
- The browser reconnects after a backend outage.
- The vehicle digital twin shows animated live CAN message flow while the simulator is running, and pauses immediately on Stop.
- Windows has a one-command launcher: `run_autoshield.ps1`.

> This is a **virtual POC simulator**, not physical CAN/HIL evidence. Raspberry Pi 5 and physical CAN validation remain separate deployment work.

## Architecture

```text
Browser dashboard
      |
      | REST / polling
      v
Python demo backend
      |
      +--> deterministic Hybrid-v4 rules
      |      allowlist / rate / DLC
      |
      +--> frozen ML specialists
             0x316 RPM / 0x43F Gear
```
## Hybrid-v4 evidence

The local demo model files are under `backend/model/`.

- `hybrid_policy.json`
- `rpm_specialist.json`
- `gear_specialist.json`

The semantic parameters mirror the frozen Hybrid-v4 artifacts audited from the B200 development workspace. The local JSON files are re-serialized for the Windows demo, so their byte hashes are not expected to match the B200 artifact hashes.

The ML specialists use the frozen feature means, scales, Logistic Regression coefficients, intercepts and probability thresholds:

- RPM `0x316`: threshold `0.9453756863`
- Gear `0x43F`: threshold `0.9314904584`

The simulator deliberately keeps RPM/Gear structural traffic inside the allowlist/rate/DLC policy so that those scenarios must cross the **ML threshold** to alert.

## Run on Windows

Prerequisites:

- Python 3.11+ in `PATH`
- Node.js 22+ / npm
- Chromium installed for Playwright only if you want browser validation

PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\run_autoshield.ps1
```

The launcher builds the dashboard, starts the backend on `http://127.0.0.1:8000`, opens the browser and shuts the backend down when you press Enter.
## Validation commands

Backend + simulator tests:

```powershell
python -m unittest discover -s tests -v
```

Frontend build/lint:

```powershell
cd dashboard
npm ci
npm run lint
npm run build
```

Browser + reconnection test:

```powershell
cd dashboard
npx playwright install chromium
npm run test:browser
```

## Expected evidence by scenario

| Scenario | Genuine Hybrid-v4 reason | Expected action |
|---|---|---|
| Normal | none | ALLOW |
| DoS | `RATE_LIMIT_EXCEEDED` | RATE_LIMIT |
| Fuzzy | `UNKNOWN_ID` | DROP |
| RPM spoof | `ML_RPM` above frozen threshold | ALERT |
| Gear spoof | `ML_GEAR` above frozen threshold | ALERT |
| Mix / Combo | interleaved `RATE_LIMIT_EXCEEDED` + `UNKNOWN_ID` + `ML_RPM` + `ML_GEAR` | per-vector action |

The dashboard Incident Log displays the reason code, human-readable evidence, action and specialist probability/threshold when applicable. Mix / Combo interleaves all four attack vectors through the same unchanged Hybrid-v4 decision path.
## Repeatable two-minute demo

**0:00–0:15 — Normal**
1. Select **Normal**.
2. Click **Start**.
3. Show green/clean traffic and `0 incidents`.
4. Click **Stop**, then **Reset**.

**0:15–0:35 — DoS**
1. Select **DoS**, click **Start**.
2. Show `RATE_LIMIT_EXCEEDED`.
3. Explain that the current 100 ms count exceeds the commissioned per-ID maximum.
4. Show action `RATE_LIMIT`.
5. Stop and Reset.

**0:35–0:55 — Fuzzy**
1. Select **Fuzzy**, click **Start**.
2. Show `UNKNOWN_ID`.
3. Explain that the injected ID is absent from the commissioned allowlist.
4. Show action `DROP`.
5. Stop and Reset.

**0:55–1:20 — RPM spoof**
1. Select **RPM spoof**, click **Start**.
2. Show that structural policy is not violated.
3. Show `ML_RPM`.
4. Point out `p > threshold` in the evidence log.
5. Stop and Reset.
**1:20–1:45 — Gear spoof**
1. Select **Gear spoof**, click **Start**.
2. Show `ML_GEAR`.
3. Point out the frozen specialist probability and threshold.
4. Stop and Reset.

**1:45–2:00 — Reliability**
1. Mention Start/Stop/Reset repeatability.
2. Point to `CONNECTED` backend status.
3. State that backend failure/reconnection is covered by automated validation.
4. Close with: **Detect locally. Decide safely. Defend at the edge.**

## Scientific scope

- Hybrid-v4 is a development/pilot artifact, not a production or safety-certified product.
- The simulator validates decision logic and evidence flow; it does not replace physical CAN/HIL testing.
- The ML specialists are vehicle/message-specific.
- No universal zero-day claim is made.
- Safety-critical automatic intervention remains policy-gated future work.
- The 100 ms observation window precedes the decision.

## Project structure

```text
backend/                  Hybrid-v4 model + simulator + HTTP server
backend/model/            frozen semantic model parameters
dashboard/                React/Vite browser dashboard
tests/                    Phase F/G Python validation
run_autoshield.ps1        Windows launcher
PHASE_F_G_VALIDATION_REPORT.md
```
