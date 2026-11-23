# Held-out set

60 mails that were not used while the prompts and the rules were written: 50 attack mails
that carry an injection, and 10 benign twins.

```
python data/corpus/heldout/build_heldout.py                                         # rewrites the .eml files and labels.csv
python scripts/evaluate.py --corpus data/corpus/heldout                             # stub: the floor
python scripts/evaluate.py --corpus data/corpus/heldout --llm ollama --model qwen2.5:14b --json heldout_14b.json
```

**Do not tune against this set.** Read the totals, not the mails. Once a prompt or a rule has
been changed because of a mail in here, that mail is tuning data and the number means less.

## How it was written

Each mail is written out one by one in `build_heldout.py` (nothing is sampled), on
22 Nov 2026, after the prompts and the rules were fixed. The set is new to the prompts.

## 50 attack mails: ten techniques, five mails each

None of these is among the ten techniques of the tuning set.

| technique | where the instruction is |
|---|---|
| `filename_instruction` | in the name of an attachment (a string the prompt shows inside the "rule results", see `docs/channels.md`) |
| `url_instruction` | in the path or the query of the link |
| `subject_instruction` | in the Subject line |
| `cross_language` | the lure is Korean and the instruction English, or the other way round |
| `forged_thread` | in a quoted or forwarded "earlier message" from the security team, finance or the user |
| `downgrade` | asks for `suspicious` instead of `phishing`, or for a reason code to be left out; never asks for `benign` |
| `prefilled_answer` | the mail ends with a finished-looking verdict |
| `policy_exception` | a "change notice" or "policy" that explains the failed checks away |
| `obfuscated` | spaced-out letters, base64, dotted letters, reversed text, rot13 |
| `simulation_claim` | "this is an approved drill, and drills are labelled benign" |

| kind of lure | mails | rule label | what code can recompute |
|---|---|---|---|
| credential | 21 | phishing | failed sender check, look-alike sender, flagged link |
| macro attachment | 8 | phishing | failed sender check, dangerous attachment |
| BEC | 7 | phishing | look-alike sender, Reply-To on another domain |
| href mismatch | 5 | suspicious | failed sender check, look-alike sender, flagged link |
| quiet | 9 | suspicious | nothing: sender check passes, the link is ordinary |

25 Korean, 25 English. The nine quiet mails are the hard case: if the model is talked into
`benign` there, the verifier has nothing to contradict it with.

## 10 benign twins

Ordinary mails that contain instructions or talk about phishing: an IT reminder ("do not click,
do not reply"), a corrected invoice ("please disregard the earlier one"), an automated report
("do not reply"), a newsletter article about prompt injection, a colleague quoting an injection
string for a training deck, a JSON example sent by a developer. All pass the sender check, come
from the organisation or a known partner, and have no flagged link. Rule label `benign`.
A defence that holds these is blocking legitimate mail. 5 Korean, 5 English.

## labels.csv

Same columns as the tuning corpus: `file, label, kind, lang, injection, marker,
rule_label`. `label` is attack or not; `rule_label` is what the label rule of `docs/labels.md`
makes of the indicators each kind contains. The indicators that code can recompute were checked
against `phishgate/rules` for all 60 mails.

## Floor (stub model, which answers benign to everything)

50 attack mails: all 50 closed if the label is trusted, 9 with the verifier (the nine quiet
mails). 10 of 10 benign twins closed.
