# IoT Incident Attribution

**In one sentence:** this project reads network traffic from a small office /
lab network, works out *which device the attack started from*, and writes a
plain-English incident report that a non-expert can act on.

---

## The problem, in plain English

When something goes wrong on a network, lots of devices start behaving oddly at
once. The obvious question — "which one was hit **first**?" — is surprisingly
hard, because:

* the noisiest device is usually a **victim**, not the source;
* perfectly innocent devices have busy days too (backups, firmware updates);
* the attacker may hop from device A to device B **through a shared server**,
  so there is no direct A→B traffic to point at.

So the naive answers ("blame whoever sent the most data", "blame whoever went
weird first") are wrong most of the time. On our hard benchmark the best of
those standard approaches is right **17%** of the time.

## What this project does instead

It reconstructs the *story*. For every device it asks: "if this device were
patient zero, how much of everything else that happened does that explain?"
The device whose story explains the most, that nothing else points at, and
that started earliest, is named as the origin.

That method is called **V5**, and on the same hard benchmark it is right
**53%** of the time first try, and has the true origin in its **top 3 90%** of
the time. When it is not confident it says so and hands over a shortlist of
three instead of guessing.

## How it is put together

```
  data/run_NNN.parquet          the network traffic for one simulated incident
        |
        v
  src/features.py               summarise each device, 60 seconds at a time
        |
        v
  src/detect.py                 learn each device's "normal", find when it broke
        |
        v
  src/attribute.py   <-- V5     build the story graph, rank the suspects
        |
        v
  src/report.py                 a local LLM writes the incident brief
        |
        v
  dashboard/app.py              one Streamlit page a human actually looks at
```

Supporting pieces:

| File | What it is for |
|---|---|
| `src/windows.py` | The single shared helper that turns a timestamp into a 60-second window number. Everything uses this one function so the maths can never drift between files. |
| `src/generate.py` | Invents realistic traffic plus a hidden attack, so we have data with a known right answer. |
| `src/evaluate.py` | Marks our homework: runs the whole pipeline many times and scores it against the truth and against four standard baselines. |
| `groundtruth/` | The true answers. **Only `src/evaluate.py` is ever allowed to look in here.** |

## The rule we do not break

`groundtruth/` holds the answer sheet. If any detection or attribution code
peeked at it, our accuracy numbers would be fiction — we would be measuring how
well the code can read the answers, not how well it can do the job.

So: **nothing inside `src/` except `evaluate.py` may read `groundtruth/`.**
This is enforced by an automated test (`tests/test_no_groundtruth_leak.py`)
which fails the build if any other file in `src/` so much as mentions the word.

## Where the numbers came from

Two prototypes were written and run first, before any project code existed:

* `sim.py` — the easy benchmark (7 devices). Method gets ~90%.
* `hard.py` — the hard benchmark (12 devices, decoys, stealthy attacker,
  relayed hops). Compares five methods; **V5 wins**.

The real project rebuilds **V5** properly, in separate testable files, and must
reproduce those numbers. If it does not, something is broken and we want to
know.

## Getting started

```bash
py -3.12 -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
pytest -q                       # all tests must pass
```

## Project status

Built in numbered steps; each step is committed separately so the history shows
how it was assembled.

- [x] Setup: environment, folders, git, this README
- [x] Step 1 — `src/windows.py` + its tests (time windows)
- [x] Step 2 — `src/generate.py` (scenario generator, hard + easy)
- [x] Step 3 — `src/features.py`
- [x] Step 4 — `src/detect.py`
- [x] Step 5 — `src/attribute.py` (V5, the core)
- [ ] Step 6 — `src/evaluate.py` (the results table)
- [ ] Step 7 — `src/report.py` (local LLM brief + validation)
- [ ] Step 8 — `dashboard/app.py` (Streamlit, with offline replay)
