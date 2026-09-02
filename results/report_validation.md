# Incident brief validation - measured behaviour

`python -m src.report --batch 20`, model `qwen3:4b` via Ollama, 20 hard runs.

The brief is only shown if it survives validation against the evidence. This
file records how often that happened, because the fallback rate is a measured
property of the system rather than a claim about it.

## Measurement 2 - current

| outcome | runs | share |
|---|---:|---:|
| passed validation first time | 11 | 55% |
| passed after one regeneration | 3 | 15% |
| rejected twice, fell back to template | 6 | 30% |

Every remaining fallback is a genuine model failure:

| run | what the model did |
|---|---|
| run_003 | timeline entries citing no evidence at all |
| run_010 | referred to "esp32", which is not a device (the devices are esp32-01 to esp32-04) |
| run_014 | no evidence cited, then invented the timestamp 03:07:00 |
| run_015 | invented evidence id `C0111927` (ids are 6 digits), and put the phrase "could not be determined" in the device field |
| run_017 | invented evidence id `C016326` |

## Measurement 1 - before the validator was corrected

| outcome | runs | share |
|---|---:|---:|
| passed validation first time | 7 | 35% |
| passed after one regeneration | 4 | 20% |
| rejected twice, fell back to template | 9 | 45% |

The first measurement was misleading, and finding out why was the point of
taking it. Most rejections were the VALIDATOR being wrong, not the model
inventing anything:

| rejection | a real invention? |
|---|---|
| `Cam2`, `ESP32-04`, `Laptop-c` "not a real device" | No - real devices, capitalised at the start of a sentence |
| `highest-ranked` "not a real device" | No - ordinary English caught by a "contains a hyphen" rule |
| `C2` "not a real device" | No - generic security vocabulary, not a claim a device exists |
| invented evidence id `C018555` | Yes |
| timestamp `03:53:00` not in the evidence | Yes |
| timeline entry citing no evidence | Yes |

### The three fixes

1. Prose is matched case-insensitively. Structured fields are still matched
   exactly, because the dashboard looks devices up by name.
2. A hyphen alone no longer marks a token as a machine name. A near-miss rule
   keeps `laptop-x` (one character from the real `laptop-c`) rejected, which
   is what a plausible fabrication actually looks like.
3. A small allowlist of generic security words (C2, HTTPS, MQTT...).

Fix 2 took two attempts: the first version compared every word against the
vocabulary and flagged the word "It" as an 80% match for "iot". The near-miss
check now runs only on tokens that are already name-shaped, and compares
against real device names only.

## What this means

Nothing unverified is ever shown. In 30% of runs the model could not produce
a brief this project is willing to display, and in those cases the reader
gets the plain template, clearly marked `LLM_FALLBACK`. That is the system
working as designed rather than failing: the alternative is showing a
confident brief containing an invented evidence id.
