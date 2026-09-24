#!/usr/bin/env python3
"""
Extract a security profile from an assessment ticket using a local Ollama model,
then score it against an answer key.

v3: forces JSON output mode, extracts fields in small batches (more reliable on
8B models than 16 fields in one shot), and salvages malformed wrappers.

Usage:
    python extract.py ticket.txt
    MODEL=qwen3:4b python extract.py ticket.txt
    python extract.py newdoc.txt --no-score     # new doc, no answer key yet
    python extract.py ticket.txt --raw          # dump raw model output for debugging
"""

import json
import os
import re
import sys
import unicodedata
import urllib.request

MODEL = os.getenv("MODEL", "qwen3:8b")
HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
NUM_CTX = int(os.getenv("NUM_CTX", "16384"))
BATCH = int(os.getenv("BATCH", "4"))

FIELDS = [
    "data_classification", "hosting_model", "hosting_location", "access_control",
    "network_exposure", "third_parties", "availability_requirements",
    "risk_owner", "change_management", "rollback_procedure", "vulnerability_scanning",
]

SCOPE_FLAGS = [
    "integration_interfaces", "deployment_endpoint_installed",
    "code_in_scope", "test_framework_in_scope", "identity_sso_claimed",
]

DEFINITIONS = {
    "hosting_model": "one of SaaS, PaaS, IaaS, on-premises",
    "hosting_location": "where the data physically resides, including region if stated",
    "third_parties": "ANY external vendor, platform, tool or service this system depends on, however the ticket describes them",
    "integration_interfaces": "interface types exposed or consumed (API, file transfer, database link, message queue)",
    "deployment_endpoint_installed": "is software installed on user endpoints? yes or no",
    "code_in_scope": "does the assessment cover source code, libraries, build pipelines or dependencies? yes or no",
    "test_framework_in_scope": "is a test automation framework in scope? yes or no",
    "identity_sso_claimed": "does the ticket claim SSO or federated identity is used? yes or no",
}

PROMPT = """Extract a structured security profile from the assessment ticket below.

Return a single JSON object with EXACTLY these top-level keys and no others:
{keylist}

The value of each key is an object with four properties. Your entire response
must look exactly like this shape:

{shape}

State rules:
- "implemented" ONLY if the ticket says it is already in place, in past or present tense
- "planned" if described in future tense ("we will", "we need to", "not yet tested", "we have not")
- "absent" if the ticket says it does not exist
- "unknown" if the ticket does not address it
- Future tense is NEVER "implemented". If the ticket says "yes" but then describes
  the action in future tense, the tense wins and the state is "planned".
- A capability that could be enabled is NOT the same as one that is enabled.

Rules:
- If the ticket does not state something: value null, state "unknown", source null
- Do not infer, assume, or fill gaps with what is typical
- Never write a source quote that does not appear in the ticket
{defs}
TICKET:
{ticket}
"""

ANSWER_KEY = {
    "data_classification":       ("implemented", ["restricted internal"]),
    "hosting_model":             ("implemented", ["saas"]),
    "hosting_location":          ("implemented", ["azure devops"]),
    "access_control":            ("implemented", ["admin"]),
    "network_exposure":          ("unknown",     []),
    "third_parties":             ("implemented", ["jfrog", "microsoft", "azure", "sonar"]),
    "availability_requirements": ("unknown",     []),
    "risk_owner":                ("implemented", ["dylan"]),
    "change_management":         ("implemented", ["template"]),
    "rollback_procedure":        ("planned",     ["uninstall", "not tested", "test"]),
    "vulnerability_scanning":    ("planned",     ["jfrog", "scan"]),
}

TRAPS = ["vulnerability_scanning", "rollback_procedure", "third_parties"]


def norm(s):
    s = unicodedata.normalize("NFKC", s or "")
    for a, b in [("\u2019", "'"), ("\u2018", "'"), ("\u201c", '"'),
                 ("\u201d", '"'), ("\u2013", "-"), ("\u2014", "-")]:
        s = s.replace(a, b)
    return re.sub(r"\s+", " ", s).strip().lower()


def call_ollama(prompt):
    body = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",          # forces syntactically valid JSON
        "options": {
            "num_ctx": NUM_CTX,
            "temperature": 0,
            "num_predict": 4096,   # stop the response being cut short
        },
    }).encode()
    req = urllib.request.Request(f"{HOST}/api/generate", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=900) as r:
        return json.loads(r.read())["response"]


def _brace_match(text, start):
    depth, in_str, esc = 0, False, False
    for i, ch in enumerate(text[start:], start):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def extract_json(text, expected):
    """Parse the response, salvaging the common wrapper-missing failure."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S | re.I)
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()

    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object found in response")

    blob = _brace_match(text, start)
    if blob:
        try:
            obj = json.loads(blob)
            # Did we get the wrapper, or just one field's innards?
            if isinstance(obj, dict) and any(k in obj for k in expected):
                return obj
        except json.JSONDecodeError:
            pass

    # Salvage: model emitted "key": {...}, "key": {...} with no outer braces.
    try:
        return json.loads("{" + text.strip().strip("{}").strip().rstrip(",") + "}")
    except json.JSONDecodeError:
        pass

    # Salvage: pull out each "key": { ... } pair individually.
    found = {}
    for m in re.finditer(r'"([a-z_]+)"\s*:\s*\{', text):
        if m.group(1) not in expected:
            continue
        sub = _brace_match(text, m.end() - 1)
        if sub:
            try:
                found[m.group(1)] = json.loads(sub)
            except json.JSONDecodeError:
                pass
    if found:
        return found

    raise ValueError("could not recover a usable object")


def extract_profile(ticket, raw_dump=False):
    """Extract in small batches — more reliable than 16 fields in one call."""
    all_fields = FIELDS + SCOPE_FLAGS
    profile = {}
    for i in range(0, len(all_fields), BATCH):
        batch = all_fields[i:i + BATCH]
        defs = "".join(f"\n- {f}: {DEFINITIONS[f]}" for f in batch if f in DEFINITIONS)
        shape = json.dumps(
            {batch[0]: {"value": "<string or null>",
                        "state": "implemented|planned|absent|unknown",
                        "confidence": "high|medium|low",
                        "source": "<exact quote or null>"},
             **{f: {"value": "...", "state": "...", "confidence": "...", "source": "..."}
                for f in batch[1:]}},
            indent=2)
        prompt = PROMPT.format(
            keylist="\n".join(f"  - {f}" for f in batch),
            shape=shape,
            defs=("\nField definitions:" + defs + "\n") if defs else "\n",
            ticket=ticket,
        )
        print(f"  fields {i+1}-{i+len(batch)} of {len(all_fields)}...", flush=True)
        raw = call_ollama(prompt)
        if raw_dump:
            print(f"--- raw ---\n{raw[:1500]}\n-----------")
        try:
            profile.update(extract_json(raw, batch))
        except Exception as e:
            print(f"    batch failed: {e}")
    return profile


def score(data, ticket):
    nt = norm(ticket)
    rows, total, bad_cites = [], 0, 0

    for f in FIELDS:
        got = data.get(f)
        if not isinstance(got, dict):
            rows.append((f, 0, "MISSING FIELD", ""))
            continue

        val, state, src = got.get("value"), (got.get("state") or "").lower(), got.get("source")
        want_state, keywords = ANSWER_KEY[f]

        if not keywords:
            val_ok = val is None or str(val).strip() == ""
        else:
            val_ok = val is not None and any(k in str(val).lower() for k in keywords)
        state_ok = state == want_state

        pts = 2 if (val_ok and state_ok) else (1 if val_ok else 0)
        total += pts

        cite = ""
        if src:
            cite = "ok" if norm(src) in nt else "NOT IN TICKET"
            if cite != "ok":
                bad_cites += 1
        elif val is not None:
            cite = "no source"

        note = []
        if not val_ok:
            note.append(f"value={val!r}")
        if not state_ok:
            note.append(f"state={state or 'missing'} (want {want_state})")
        rows.append((f, pts, "; ".join(note), cite))

    w = max(len(f) for f in FIELDS)
    print(f"\n{'FIELD'.ljust(w)}  PTS  CITE          NOTES")
    print("-" * (w + 48))
    for f, pts, note, cite in rows:
        flag = " *" if f in TRAPS else "  "
        print(f"{f.ljust(w)}{flag}{pts:>3}  {cite.ljust(13)} {note}")
    print("-" * (w + 48))
    print(f"SCORE: {total}/{len(FIELDS) * 2}")
    print(f"CITATIONS NOT FOUND IN TICKET: {bad_cites}")
    trap_pts = sum(p for f, p, _, _ in rows if f in TRAPS)
    print(f"TRAP SCORE: {trap_pts}/{len(TRAPS) * 2}   (* marks trap fields)")

    print("\nSCOPE FLAGS (not scored — these drive coverage.py triggers)")
    for f in SCOPE_FLAGS:
        g = data.get(f) or {}
        print(f"  {f.ljust(30)} {str(g.get('value'))[:40]:<42} [{g.get('state', '?')}]")
    return total


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        sys.exit(1)

    ticket = open(args[0], encoding="utf-8").read()
    print(f"model={MODEL}  num_ctx={NUM_CTX}  batch={BATCH}  ticket={args[0]} "
          f"({len(ticket)} chars, ~{len(ticket)//4} tokens)")
    if len(ticket) // 4 > NUM_CTX * 0.7:
        print("WARNING: ticket may not fit in context. Raise NUM_CTX or chunk it.")

    print("calling model...")
    data = extract_profile(ticket, raw_dump="--raw" in sys.argv)

    missing = [f for f in FIELDS + SCOPE_FLAGS if f not in data]
    if missing:
        print(f"\nfields not returned: {', '.join(missing)}")

    out = args[0].rsplit(".", 1)[0] + f".{MODEL.replace(':', '-')}.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print(f"saved -> {out}  ({len(data)} fields)")

    if "--no-score" not in sys.argv:
        score(data, ticket)


if __name__ == "__main__":
    main()
