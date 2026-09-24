#!/usr/bin/env python3
"""
Coverage engine — turns a document plus the question bank into a
prioritised follow-up questionnaire.

Three stages:
  1. TRIGGER   pure code, no model. Which questions apply to this system?
  2. COVERAGE  model. Does the document answer each one, to the evidence standard?
  3. ESCALATE  pure code. Where a tier 1/2 answer fails, add the tier 3 follow-up.

Usage:
    python coverage.py ticket.txt question-bank-v1.csv
    python coverage.py ticket.txt question-bank-v1.csv --profile ticket.qwen3-8b.json
    MODEL=qwen3:4b python coverage.py ticket.txt question-bank-v1.csv
"""

import csv
import json
import os
import re
import sys
import unicodedata
import urllib.request

MODEL = os.getenv("MODEL", "qwen3:8b")
HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
NUM_CTX = int(os.getenv("NUM_CTX", "16384"))
BATCH = int(os.getenv("BATCH", "6"))

# ---------------------------------------------------------------- triggers
# Recognised trigger expressions -> function of the profile.
# Anything not listed here is reported as 'manual' rather than silently
# included or dropped. That list is the analyst's review queue.

def _get(profile, path):
    cur = profile
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    if isinstance(cur, dict):
        cur = cur.get("value")
    return cur


def _truthy(v):
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return s not in ("", "none", "null", "no", "false", "n/a", "unknown")


TRIGGERS = {
    "always":
        lambda p: True,
    "integration.interfaces contains api":
        lambda p: "api" in str(_get(p, "integration") or _get(p, "integration.interfaces") or "").lower(),
    "third_parties is not empty":
        lambda p: _truthy(_get(p, "third_parties")),
    "hosting.model = saas":
        lambda p: "saas" in str(_get(p, "hosting_model") or "").lower(),
    "deployment.endpoint_installed = true":
        lambda p: _truthy(_get(p, "deployment_endpoint_installed")),
    "code in scope":
        lambda p: _truthy(_get(p, "code_in_scope")),
    "code.dependencies in scope":
        lambda p: _truthy(_get(p, "code_in_scope")),
    "code.test_framework in scope":
        lambda p: _truthy(_get(p, "test_framework_in_scope")),
}


def evaluate_trigger(trigger, profile):
    """Returns True (in scope), False (out of scope), or 'manual'."""
    t = (trigger or "").strip().lower()
    if t in TRIGGERS:
        return TRIGGERS[t](profile)
    if t.startswith("tier "):
        return False           # escalation — handled in stage 3, not here
    return "manual"


# ---------------------------------------------------------------- model call
def call_ollama(prompt):
    body = json.dumps({
        "model": MODEL, "prompt": prompt, "stream": False,
        "options": {"num_ctx": NUM_CTX, "temperature": 0},
    }).encode()
    req = urllib.request.Request(f"{HOST}/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=900) as r:
        return json.loads(r.read())["response"]


def extract_json(text):
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S | re.I)
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M)
    start = min([i for i in (text.find("["), text.find("{")) if i != -1] or [-1])
    if start == -1:
        raise ValueError("no JSON found")
    opener = text[start]
    closer = "]" if opener == "[" else "}"
    depth, in_str, esc = 0, False, False
    for i, ch in enumerate(text[start:], start):
        if in_str:
            if esc: esc = False
            elif ch == "\\": esc = True
            elif ch == '"': in_str = False
        elif ch == '"': in_str = True
        elif ch == opener: depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unterminated JSON")


COVERAGE_PROMPT = """You are checking whether a document answers specific assessment questions.

For EACH question below, decide:
  "answered"      the document answers it AND meets the evidence standard
  "partial"       the document touches on it but falls short of the evidence standard
  "absent"        the document does not address it
  "contradictory" the document gives conflicting information

Rules:
- Quote the document verbatim in "evidence". If nothing relevant exists, use null.
- Never write an evidence quote that does not appear in the document.
- A stated intention is NOT an implemented control. If the document describes
  something in future tense ("we will", "we need to", "not yet tested"), the
  status is "partial" and note that it is planned rather than in place.
- A capability that could be enabled is NOT the same as one that is enabled.
- Judge against the evidence standard given, not against the question alone.

Return ONLY a JSON array, one object per question, in the same order:
[{{"id": "<id>", "status": "...", "evidence": "<quote or null>", "shortfall": "<what is missing, or null>"}}]

QUESTIONS:
{questions}

DOCUMENT:
{document}
"""


def check_coverage(questions, document):
    results = {}
    for i in range(0, len(questions), BATCH):
        batch = questions[i:i + BATCH]
        qtext = "\n\n".join(
            f'id: {q["id"]}\nquestion: {q["question"]}\nevidence standard: {q["expected_evidence"]}'
            for q in batch
        )
        print(f"  checking {i + 1}-{i + len(batch)} of {len(questions)}...", flush=True)
        try:
            raw = call_ollama(COVERAGE_PROMPT.format(questions=qtext, document=document))
            for item in extract_json(raw):
                if isinstance(item, dict) and item.get("id"):
                    results[item["id"]] = item
        except Exception as e:
            print(f"    batch failed: {e}")
    return results


# ------------------------------------------------------------------ helpers
def norm(s):
    s = unicodedata.normalize("NFKC", s or "")
    for a, b in [("\u2019", "'"), ("\u2018", "'"), ("\u201c", '"'),
                 ("\u201d", '"'), ("\u2013", "-"), ("\u2014", "-")]:
        s = s.replace(a, b)
    return re.sub(r"\s+", " ", s).strip().lower()


PRIORITY_ORDER = {"Critical": 0, "Standard": 1, "Contextual": 2}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) < 2:
        print(__doc__)
        sys.exit(1)

    document = open(args[0], encoding="utf-8").read()
    bank = list(csv.DictReader(open(args[1], encoding="utf-8")))
    for q in bank:
        q["tier"] = int(q["tier"])

    profile = {}
    if "--profile" in sys.argv:
        idx = sys.argv.index("--profile")
        if idx + 1 < len(sys.argv):
            profile = json.load(open(sys.argv[idx + 1], encoding="utf-8"))
            print(f"loaded profile: {sys.argv[idx + 1]}")
    if not profile:
        print("no profile supplied — 'always' triggers only, everything else manual")

    # ---------------------------------------------------------- stage 1
    in_scope, manual = [], []
    for q in bank:
        if q["tier"] == 3:
            continue                      # escalation only
        r = evaluate_trigger(q["trigger"], profile)
        if r is True:
            in_scope.append(q)
        elif r == "manual":
            manual.append(q)

    print("\n" + "=" * 72)
    print("STAGE 1 — TRIGGER")
    print("=" * 72)
    print(f"  {len(in_scope)} in scope · {len(manual)} need an analyst decision "
          f"· {len(bank)} in bank")
    if manual:
        print("\n  Triggers not machine-evaluable — analyst review queue:")
        seen = set()
        for q in manual:
            if q["trigger"] not in seen:
                seen.add(q["trigger"])
                print(f"    · {q['trigger']}")

    if not in_scope:
        print("\nNothing in scope. Supply a profile with --profile.")
        sys.exit(0)

    # ---------------------------------------------------------- stage 2
    print("\n" + "=" * 72)
    print(f"STAGE 2 — COVERAGE  ({MODEL})")
    print("=" * 72)
    results = check_coverage(in_scope, document)

    ndoc = norm(document)
    gaps, answered, bad_cites = [], [], 0
    for q in in_scope:
        r = results.get(q["id"])
        if not r:
            q["_status"], q["_shortfall"], q["_evidence"] = "unchecked", "model did not return a result", None
            gaps.append(q)
            continue
        status = (r.get("status") or "").lower()
        ev = r.get("evidence")
        if ev and norm(ev) not in ndoc:
            bad_cites += 1
            ev = f"[NOT IN DOCUMENT] {ev}"
        q["_status"], q["_shortfall"], q["_evidence"] = status, r.get("shortfall"), ev
        (answered if status == "answered" else gaps).append(q)

    # ---------------------------------------------------------- stage 3
    escalations = []
    failed_topics = {(q["domain"], q["topic"]) for q in gaps}
    in_scope_ids = {q["id"] for q in in_scope}
    for q in bank:
        is_escalation = q["tier"] == 3 or (q["trigger"] or "").strip().lower().startswith("tier ")
        if is_escalation and q["id"] not in in_scope_ids and (q["domain"], q["topic"]) in failed_topics:
            escalations.append(q)

    # ------------------------------------------------------------- output
    total = len(in_scope)
    score = len(answered) / total * 100 if total else 0

    print("\n" + "=" * 72)
    print("RESULT")
    print("=" * 72)
    print(f"  Coverage score: {score:.0f}%  ({len(answered)}/{total} answered)")
    print(f"  Gaps: {len(gaps)} · Escalations triggered: {len(escalations)}")
    if bad_cites:
        print(f"  ** {bad_cites} evidence quotes not found in the document **")

    gaps.sort(key=lambda q: (PRIORITY_ORDER.get(q["priority"], 3), q["domain"]))

    print("\n" + "-" * 72)
    print("QUESTIONNAIRE — send these")
    print("-" * 72)
    n = 0
    for q in gaps:
        n += 1
        print(f"\n{n}. [{q['priority']}] {q['question']}")
        print(f"   domain: {q['domain']} · status: {q['_status']}")
        if q.get("_shortfall"):
            print(f"   why: {q['_shortfall']}")
        if q.get("_evidence"):
            print(f"   document says: {q['_evidence'][:150]}")

    if escalations:
        print("\n" + "-" * 72)
        print("ESCALATIONS — ask if the above come back thin")
        print("-" * 72)
        for q in escalations:
            print(f"\n· {q['question']}")
            print(f"  standard: {q['expected_evidence']}")

    out = args[0].rsplit(".", 1)[0] + ".coverage.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({
            "model": MODEL,
            "coverage_score": round(score),
            "in_scope": total,
            "answered": [q["id"] for q in answered],
            "gaps": [{k: v for k, v in q.items()} for q in gaps],
            "escalations": [q["id"] for q in escalations],
            "manual_triggers": sorted({q["trigger"] for q in manual}),
            "citations_not_found": bad_cites,
        }, fh, indent=2, ensure_ascii=False)
    print(f"\nsaved -> {out}")


if __name__ == "__main__":
    main()
