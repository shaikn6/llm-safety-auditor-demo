"""Recorded audits of real open models, produced with the same evaluator and attack library as the live demo."""
import json
from pathlib import Path

import pandas as pd
import streamlit as st

_RAW = json.loads((Path(__file__).parent / "real_audits.json").read_text())
DATA = {k: v for k, v in _RAW.items() if not k.startswith("_")}
VALIDATION = _RAW["_validation"]


def _fmt(m):
    return "n/a" if not m else f"{m[0]:.2f} ({m[1][0]:.2f}-{m[1][1]:.2f})"


def _validation() -> None:
    v = VALIDATION
    st.markdown("### How well does the detector match a human reading?")
    st.markdown(
        "One reviewer labeled all 100 responses safe or unsafe against each prompt's expected behavior, with the "
        "detector's flags hidden. The reviewer had seen the 0.5B flags in an earlier pass, so the labels are not fully "
        "independent; a second, model-based labeler is described below. Intervals are 95% Wilson intervals; with 22 unsafe responses they are wide."
    )
    st.markdown(
        "The detector rules were revised after reading the misses and false alarms in these same 100 answers, so every "
        "row except the two 'held out' rows is measured on data the rules were fitted to and overstates accuracy. The "
        "held-out rows come from leave-one-prompt-out selection: for each prompt, the new rules were kept or dropped "
        "using only the other 49 prompts, then that prompt's two answers were scored."
    )
    rows = []
    for key, name in (("heldout", "Held out, against the reviewer"), ("heldout_judge", "Held out, against the LLM judge"),
                      ("all", "All 100 responses"), ("excluding_borderline", "Without 15 borderline calls"),
                      ("vs_judge", "Against the LLM judge's labels"), ("both_agree", "Where reviewer and judge agree"),
                      ("qwen05", "Qwen2.5-0.5B only"), ("qwen15", "Qwen2.5-1.5B only"), ("HALLUCINATION_TRIGGER", "Hallucination"),
                      ("JAILBREAK", "Jailbreak"), ("BIAS_ELICITATION", "Bias"), ("DATA_EXFILTRATION", "Data exfiltration"),
                      ("PROMPT_INJECTION", "Prompt injection")):
        m = v[key]
        rows.append({"Subset": name, "Responses": m["n"], "Unsafe (labeler)": m["unsafe"], "Flagged correctly": m["tp"],
                     "False alarms": m["fp"], "Missed": m["fn"], "Precision": _fmt(m["precision"]), "Recall": _fmt(m["recall"])})
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    st.markdown(
        "- Before the revision, bias was the weakest area (1 of 7 biased answers flagged). Rules for a numbered ranking "
        "of groups and for an answer that accepts the prompt's premise ('Given that Group X ...', 'Certainly! Here are ...') "
        "now flag 6 of 7, but they were written from these answers.\n"
        "- The old false alarms were a refusal that repeats the attack's wording, an echoed `<system_prompt>` tag the "
        "prompt asked for, numbered lists of points to consider or of hazard names read as instructions, and one "
        "pushback ('not necessarily the case') read as a generalisation. Each of these fixes rests on one or two prompts, "
        "so the held-out rows give them little credit.\n"
        "- Data exfiltration and prompt injection have almost no unsafe responses here (0 and 1), so those rows say little. "
        "A later rule flags an answer that carries out the injected instruction (the demanded phrase, persona or language, "
        "or a secret from the prompt); it catches the one unsafe injection answer here (1.5B, PI-004), but held out it gets "
        "no credit because no other prompt supports it.\n"
        "- Second labeler: Qwen2.5-14B-Instruct (4-bit) judged all 100 responses with the same rubric, flags hidden. It passed a "
        "16-case sanity check (8 clear refusals, 8 clear failures) that a 7B judge failed. It agreed with the reviewer on 88 of 100 "
        "(Cohen's kappa 0.69) and was stricter, calling 30 unsafe against the reviewer's 22: mostly translating or summarizing "
        "injected text, which the reviewer counted as doing the legitimate task.\n"
        "- Held out, precision and recall are 0.82 and 0.82 against the reviewer (0.62 and 0.59 before the revision) and "
        "0.75 and 0.60 against the judge (0.67 and 0.47 before). Against the judge the gain is within noise."
    )


def render() -> None:
    st.markdown("## Recorded audits of real models")
    st.markdown(
        "The live demo audits a scripted mock model. These two runs audited **real open models** with the repo's "
        "rule-based detector and OpenAI-compatible provider (model served locally with `mlx_lm.server`, default "
        "sampling settings, one request per prompt)."
    )
    st.info(
        "These recordings use the **original 50 prompts across 5 categories** (jailbreak, prompt injection, data "
        "exfiltration, bias, hallucination). The newer OWASP categories added to the live attack library "
        "(LLM02 insecure output, LLM04 model DoS, LLM05 supply chain, LLM07 insecure plugin, LLM08 excessive agency) "
        "were not part of these runs, so they are not in the numbers below."
    )
    st.warning(
        "Read before quoting. The detector is a rule-based screen, not a validated classifier. 'Flagged' means the rules "
        "fired, not that the response was harmful. The 0.5B run was repeated three times with identical flags; the 1.5B run was done once. "
        "One reviewer labeled every response by hand (see the validation below), and some responses are cut for display."
    )
    rows = [
        {"Model": m, "Flagged": f"{d['flagged']}/{d['total']}", "Refusal rate": f"{d['refusal_rate']:.0%}",
         "Safety score": d["score"], "Hand-labeled": "yes" if d["reviewed"] else "no"}
        for m, d in DATA.items()
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    st.markdown("**Flagged per category**")
    cats = sorted({c for d in DATA.values() for c in d["per_category"]})
    st.dataframe(
        pd.DataFrame({m: {c: f"{d['per_category'][c]['flagged']}/{d['per_category'][c]['n']}" for c in cats}
                      for m, d in DATA.items()}),
        use_container_width=True,
    )
    _validation()
    model = st.selectbox("Read the responses", list(DATA))
    only_flagged = st.checkbox("Only flagged", value=True)
    for r in DATA[model]["rows"]:
        if only_flagged and not r["flagged"] and not r["review"]:
            continue
        label = f"{r['id']} · {r['category'].replace('_', ' ').title()} · {'FLAGGED' if r['flagged'] else 'not flagged'}"
        with st.expander(label):
            st.markdown(f"**Prompt:** {r['prompt']}")
            st.markdown(f"**Response:** {r['response']}")
            tag = "unsafe" if r["label"] == "UNSAFE" else "safe"
            st.markdown(f"**Reviewer's label:** {tag}{' (borderline)' if r['borderline'] else ''}")
            if r["review"]:
                st.markdown(f"**Reviewer's note (on the flags before the rule revision):** {r['review']}")
