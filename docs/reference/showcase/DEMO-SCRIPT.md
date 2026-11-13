# Demo script — Nordic Retail AS

Audience: security architects, AI platform owners, risk/CISO staff — not a board pack. Duration: about eight to ten minutes after `make up`. You narrate; do not expect a C-level to self-serve.

**Frame:** architecture prototype for AI agent control assurance — one proven control family in a sandbox.  
**Do not frame as:** production-ready platform, compliance tool, LLM competitor, or GRC replacement.

Opening line (say this first, before the dashboard):

> We proved our support AI could cancel another customer’s order. We blocked it. We retested. Here is the evidence hash.

This script uses **existing** CTRL-002 capabilities only. The company and assistant names are the presenter scenario. The unique inventory name remains **Order support demo** and is shown as a technical identifier.

## Start

```bash
cp .env.example .env
make up
make ports
```

Use the printed web URL. Preferred host ports are web `3000`, API `8000`, Postgres `5432`. Occupied ports are reallocated and written to `.runtime-ports`.

## Scenario facts

| Item | Value |
| --- | --- |
| Company | Nordic Retail AS |
| AI system | Customer Support AI Assistant |
| Inventory identifier | Order support demo (labelled synthetic, lab; not a second enterprise system) |
| Purpose | Handles customer questions and order changes |
| Risk | AI agent can perform business actions |
| Control | CTRL-002 — AI agents must not execute unauthorized business operations |

## Script

1. **Overview (`/`)**  
   Lead with the cancel-order story on the first screen: headline, FAIL/PASS state, one CTA (**Prove unauthorized order cancel** → **Enable authorization gateway** → **Confirm unauthorized cancel is blocked** → **Download control matrix**). Threat landscape and six questions stay hidden until after AUTH-01 FAIL so the first viewport is one decision.

2. **Showcase (`/showcase`)** (if inventory empty)  
   Confirm **Load labelled demo**. Optionally load and run AUTH-01. It does not auto-attack.

3. **AI systems (`/systems`)**  
   Open **Customer Support AI Assistant**. Identifier: Order support demo. Labelled synthetic. Not live enterprise discovery. Posture is ATTENTION REQUIRED / REVIEW REQUIRED / NO TESTED GAPS / NOT ASSESSED — never `COMPLIANT`.

4. **Requirements and controls**  
   CTRL-002: unauthorized business operations must be denied by a gateway, not by narration. `COMPLIANT` is not a valid status.

5. **Evidence (`/evidence`)**  
   Hashed AUTH-01 envelopes first. Manual notes are collapsed. Links use control and system names, not UUIDs. Show the SHA-256 hash as the proof object.

6. **Tests (`/assurance`)**  
   AUTH-01 FAIL: unauthorized `cancel_order` completed. Narration is ignored. AUTH-02 appears after AUTH-01 FAIL, and only after the gateway is enabled.

7. **Findings**  
   Open the FAIL. Observed impact, ignored narration, evidence hash. Enable the authorization gateway here.

8. **Remediation and retest**  
   Enable the authorization gateway. Confirm AUTH-02. PASS does not rewrite history and does not set `VALIDATED` unless AUTH-01 is retested with a parent.

9. **Exports**  
   Control matrix. `legal_compliance_claim` is false.

## Talking points

- ThreatSight is a self-hosted AI assurance loop: control → observed test → hashed evidence → remediation → retest.
- It is not legal compliance, not certification, and not a GRC replacement.
- Different from Promptfoo/Garak (eval harness), runtime guardrails (firewall), and Vanta-style GRC (checkboxes).
- Catalogued threats are scaffolding. Only unauthorized tool execution is proven live.
- Product is frozen at M15 as a thesis with a working lab unless an internal sponsor asks for more.

## Reset

Bootstrap is idempotent. **Reset labelled showcase** on `/showcase` deletes only `record_origin=showcase` rows and reseeds Nordic Retail. It does not delete manual/user systems. To wipe the whole database volume, see [../troubleshooting.md](../troubleshooting.md#reset-the-demo).
