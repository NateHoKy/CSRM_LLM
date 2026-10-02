# CSRM_LLM

Reads a risk assessment ticket and produces a prioritised follow-up questionnaire.
Runs locally — no document content leaves your machine.

---

## Setup

**1. Install [Ollama](https://ollama.com) and pull a model:**

```powershell
ollama pull qwen3:8b
```

Use `qwen3:4b` if you have less than 8 GB of VRAM.

**2. Confirm it's running:**

```powershell
curl.exe http://localhost:11434/api/tags
```

**3. Create a folder for your tickets:**

```powershell
mkdir data
```

Save each ticket as a plain `.txt` file — copy the text straight out of the
ticketing system without tidying it. `data\` is gitignored, so anything you put
there stays local.

Python 3.9+ is the only other requirement. Nothing to install.

---

## Step 1 — extract the profile

```powershell
python extract.py data\ticket.txt
```

Works through the fields in four batches, then prints a score table.

**Produces** `data\ticket.qwen3-8b.json` — the structured security profile.

**Reading the table:**

```
FIELD                      PTS  CITE          NOTES
vulnerability_scanning    *  2  ok
third_parties             *  1  ok            state=unknown (want implemented)
```

| Column | Meaning |
|---|---|
| `PTS` | 2 = value and state both correct · 1 = value right, state or citation wrong · 0 = wrong or missing |
| `CITE` | `ok` = the quote was found in the ticket |
| `*` | Trap field — tests whether the model can tell an existing control from a planned one. Watch these more than the total |

Below the table, the scope flags show what the profile detected — hosting model,
third parties, whether code is in scope. These drive which questions get asked in
step 2.

---

## Step 2 — generate the questionnaire

```powershell
python coverage.py data\ticket.txt question-bank-v1.csv --profile data\ticket.qwen3-8b.json
```

The `--profile` filename comes from step 1 and is built from the model name. Check
it with `dir data\*.json` if unsure.

**Produces** the questionnaire on screen and `data\ticket.coverage.json`.

**What you'll see:**

```
STAGE 1 — TRIGGER
  105 triggered · 48 after collapsing to one question per topic · 11 need an analyst decision

STAGE 2 — COVERAGE (qwen3:8b)
  checking 1-6 of 48...

RESULT
  Coverage score: 8%  (4/48 answered)
  Citations: 23 verbatim · 9 paraphrased · 0 not in document · 16 none given
```

Then the questions themselves, Critical first, each showing what the document said
and what's missing. Below them, escalation questions to hold back and ask only if
the first round comes back thin.

| Line | What it tells you |
|---|---|
| Coverage score | How much of the applicable ground the ticket already covers |
| Manual triggers | Questions the engine couldn't decide on — your review queue |
| Citations | `paraphrased` = summarised rather than quoted · `not in document` = unsupported |

**The output is a draft.** Review every question before sending any of it.

---

## Options

```powershell
$env:MODEL="qwen3:4b"      # different model
$env:NUM_CTX="8192"        # smaller context window
$env:BATCH="2"             # fewer items per model call
```

Clear with `$env:MODEL=""`.

| Flag | Effect |
|---|---|
| `--no-score` | Skip scoring — for a new document with no answer key |
| `--raw` | Print the raw model output |

---

## Saving output

```powershell
python extract.py data\ticket.txt 2>&1 | Tee-Object data\run1.txt
```

Prints to screen and saves to the file. PowerShell only.

---

## Before committing

Tickets contain Restricted Internal information. `.gitignore` covers the obvious
patterns, but check each time:

```powershell
git ls-files | findstr /i "ticket run qwen coverage.json"
```

No output is the correct result.

---

## Files

| File | Purpose |
|---|---|
| `extract.py` | Step 1 — profile extraction and scoring |
| `coverage.py` | Step 2 — questionnaire generation |
| `question-bank-v1.csv` | 105 questions across 16 control domains |
| `.gitignore` | Data exclusion rules |
| `data\` | Your tickets and output — gitignored |

---

## Scope

Plain text input only — copy content out of PDFs and Word documents manually.
Long Solution Architecture Documents will exceed the context window.

The tool does not assign risk ratings. It supplies the facts a rating rests on,
each with a citation. An analyst makes the rating.
