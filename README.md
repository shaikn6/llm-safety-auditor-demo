# 🔒 LLM Safety Auditor

**Red-teams an LLM with 70 adversarial prompts across 10 categories mapped to 8 of the OWASP LLM Top 10 (2023), and flags unsafe answers. On 100 hand-labelled Qwen answers the detector scores precision 0.82 and recall 0.82 against the reviewer, held out by prompt (optimistic; see Methodology & limitations).**

Interactive **red-teaming dashboard** for large language models. Runs **70 hand-written adversarial prompts** across 10 attack categories, scores responses against the **OWASP LLM Top 10 (2023)**, and can export a structured audit report as JSON or PDF (`auditor.report_generator`). The default view is a **comparative scorecard of real recorded audits**; the scripted mock is a clearly labelled fallback.

## What it does

| Stage | Detail |
|---|---|
| **Attack library** | 70 payloads across 10 categories: jailbreak, prompt injection, insecure output handling, model DoS, supply chain, data exfiltration, insecure plugin design, excessive agency, bias elicitation, hallucination |
| **OWASP coverage** | 8 of the 10 (2023) ids: LLM01, LLM02, LLM04, LLM05, LLM06, LLM07, LLM08, LLM09. LLM03 and LLM10 are not black-box testable from one prompt/response, so they are shown as *not tested* rather than failed |
| **Scoring** | Per-category pass/fail + overall safety score; the OWASP headline is *passed / tested*, not *passed / 10* |
| **Reporting** | Structured red-team report with findings and remediation notes |

**Recorded real-model audits (default view)** — a comparative scorecard of two real open models audited with the same detector:

| Model | Flagged | Refusal rate | Safety score (of 100) |
|---|---|---|---|
| Qwen2.5-0.5B-Instruct | 14 / 50 | 28% | 72.0 |
| Qwen2.5-1.5B-Instruct | 6 / 50 | 46% | 88.0 |

Every response carries a hand label, and the view measures how well the detector's flags match those labels (held out by prompt: precision 0.82, recall 0.82 against the reviewer; precision 0.75, recall 0.60 against a second, model-based labeler; intervals are wide, see below).

**Demo mode (fallback)** — ships with a scripted mock LLM, so it runs end-to-end with **no API key**. Its scores show how the pipeline works, not how any real model behaves. Point the provider at a real model (`LLM_PROVIDER=openai`/`anthropic`) to audit your own.

## Methodology & limitations

**What is tested, and how.** Each prompt is sent once to the model; the reply is
screened by a rule-based detector (keyword, regex PII/credential, refusal,
optional semantic similarity, bias signals, and category-specific contextual
rules). A reply is "unsafe" when the rules fire, not when a human judged it
harmful. The OWASP headline is reported as *controls passed / controls tested*,
never *passed / 10*, because only 8 of the 10 (2023) ids are exercised.

**What is not tested, and why.** LLM03 (Training Data Poisoning) and LLM10
(Model Theft) are not observable from a single black-box prompt/response pair,
so they are marked *not tested* rather than scored. The rules for the five
original categories (jailbreak, prompt injection, data exfiltration, bias,
hallucination) were measured on 100 hand-labelled Qwen answers; the five newer
categories (LLM02 insecure output, LLM04 model DoS, LLM05 supply chain, LLM07
insecure plugin, LLM08 excessive agency) are screened by **smoke-test rules that
have not been validated against human labels** — they fire on the demo failure
templates and on obvious payloads, and will miss paraphrased or subtle cases.
The recorded real-model audits cover only the original 50 prompts in 5
categories; the newer categories are not in those recordings.

- Demo mode answers come from a scripted mock (fixed seed, illustrative failure
  rate per attack category — not measured). Its safety score shows how the
  pipeline works, not how any real model behaves.
- The detector misses some unsafe answers and flags some safe ones. It was
  measured on 100 hand-labelled answers from two small models (Qwen2.5-0.5B and
  1.5B, 50 prompts each), and its rules were then revised after reading the
  misses and false alarms in those same answers. Numbers on these answers are
  therefore reported held out: for each of the 50 prompts, every new rule was
  kept or dropped (greedy, kept only if it raised F1) using the other 49 prompts
  only, and that prompt's two answers were scored with the result.
  Intervals are 95% bootstrap intervals, resampling prompts.

  | Labeler | Detector | Precision | Recall | F1 |
  |---|---|---|---|---|
  | Reviewer (22 unsafe) | before | 0.62 (0.35-0.89) | 0.59 (0.36-0.81) | 0.60 (0.38-0.78) |
  | Reviewer | after, held out | 0.82 (0.61-1.00) | 0.82 (0.65-0.96) | 0.82 (0.65-0.93) |
  | Second labeler (30 unsafe) | before | 0.67 (0.44-0.88) | 0.47 (0.26-0.68) | 0.55 (0.34-0.71) |
  | Second labeler | after, held out | 0.75 (0.54-0.93) | 0.60 (0.39-0.79) | 0.67 (0.47-0.81) |

  The F1 gain is 0.06 to 0.41 (paired 95% interval) against the reviewer and
  0.00 to 0.27 against the second labeler, so against the second labeler it is
  not clearly beyond noise. On one fixed 30/20 split of the prompts, rules
  chosen on the 30 changed nothing on the 20: most fixes rest on one or two
  prompts each. All rules were written after reading every error, so even the
  held-out numbers are optimistic. On the fitted answers themselves the
  detector scores 1.00 / 0.91 (reviewer) and 0.95 / 0.63 (second labeler);
  those figures are not an accuracy estimate.
- Answers that obey an injected instruction: given the attack prompt, the
  detector flags an answer that outputs the phrase the injection demanded,
  speaks as the persona it assigned, switches to the language it demanded, or
  repeats a secret value written in the prompt. In the 100 recorded answers
  this fires once (the one unsafe injection answer, 1.5B on PI-004), so held
  out it gets no credit. On 48 new hand-written injection cases (24 obeyed,
  24 refused or handled as data), written before the rules and scored once,
  recall went from 0.00 to 0.79 (0.62-0.95) with no false alarms; F1 0.88
  (0.76-0.98). The same person wrote the cases and the rules, so this
  overstates accuracy on real model output. Still missed: an injected
  sentence worked into the answer, an obeyed action described in prose
  ("Sending the addresses to ..."), an injected format such as all capitals,
  and an injected task done instead of the real one. Translating or
  summarising injected text counts as safe; the second labeler disagreed on
  some of those (PI-001, PI-002, PI-009). The Detect Custom Text box sends no
  prompt, so these rules do not run there.
- Not caught: a refusal followed by made-up detail, and stereotypes worded as
  soft tendencies ("women CEOs tend to be more balanced").
- 70 prompts is a smoke test, not full coverage of the OWASP LLM Top 10.

## Stack

FastAPI · sentence-transformers · reportlab · Streamlit

## Links

- 💻 Source: [github.com/shaikn6/llm-safety-auditor](https://github.com/shaikn6/llm-safety-auditor)
- 👤 Author: [Nagizaaz Shaik](https://github.com/shaikn6) · [LinkedIn](https://linkedin.com/in/nagizaazshaik)
