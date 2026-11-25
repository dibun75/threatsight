# Threatsight and the EU AI Act

Threatsight is not a compliance checker. It cannot tell you whether a system meets Regulation (EU) 2024/1689. Most of the Act is about risk classification, documentation, data governance and human oversight, which an agent test does not cover.

What it does give you is evidence for one part: how an AI agent behaves when someone tries to talk it into misusing its tools. Each assessment report has an "Evidence for the EU AI Act" section, and `GET /api/world/runs/{id}` returns the same data as `ai_act`.

| Article | What the report offers |
|---|---|
| Article 15(5), robustness and cybersecurity | Whether a hostile instruction led to a harmful action, and whether a guardrail stopped it on retest. A failed run is shown as a gap to fix, and an untried attack as no evidence. |
| Article 9, risk management | A foreseeable misuse risk was identified, tested with a defined pass or fail check and retested. |
| Article 12, record-keeping | Every step is in a hash-chained evidence log that can be checked afterwards. |
| Article 14, human oversight | Only when a high-risk action was held for a named person to approve or reject. |

The mapping is our reading of the Act's text, not a legal opinion. Use the report as supporting evidence in your technical documentation, and get legal advice on whether and how the Act applies to your system.

Application dates: the Digital Omnibus on AI moved the high-risk obligations to 2 December 2027 (stand-alone Annex III systems) and 2 August 2028 (Annex I products), as reported by law firms in mid-2026. Check the Official Journal for the dates that apply to you.
