"""The label part of the analysis prompt (S1) and the rule label in the corpus.

The labels in schemas/verdict.py are the contract. The prompt must carry that
definition word for word, outside the data block, and the generated corpus must
carry the label the rule gives for the reason codes the generator plants.
"""
import csv
import importlib.util
import subprocess
import sys
from pathlib import Path

from phishgate.agents import StubLLM
from phishgate.intake.prompt_assembly import DATAMARK, build_analysis_prompt
from phishgate.rules.facts import rule_summary
from phishgate.schemas import Label

ROOT = Path(__file__).resolve().parent.parent
RULE_LINE = "(d) suspicious_link AND credential_request"       # last clause of the rule, word for word from the schema


def test_prompt_carries_the_label_rule_outside_the_data_block(injected_msg):
    system, user = build_analysis_prompt(injected_msg, rule_summary(injected_msg))
    assert RULE_LINE in system
    assert "Consistency, checked by code" in system
    assert system.index("untrusted") < system.index(RULE_LINE)              # fixed instructions first, then the rule
    assert "<<DATA" not in system and DATAMARK not in system and "SECURITY TEAM NOTE" not in system
    assert RULE_LINE not in user                                             # never inside the user turn


def test_corpus_labels_carry_the_rule_label_and_evaluation_reports_it(tmp_path):
    out = tmp_path / "generated"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "make_corpus.py"), "--out", str(out), "--benign", "6",
                    "--phishing", "10", "--injected", "4", "--markers", "0"], check=True, capture_output=True)
    rows = list(csv.DictReader((out / "labels.csv").open(encoding="utf-8")))
    assert len(rows) == 20
    labels = {l.value for l in Label}
    for r in rows:
        assert r["rule_label"] in labels and (r["rule_label"] == "benign") == (r["label"] == "benign")
    soft = {r["rule_label"] for r in rows if r["kind"] in ("quiet", "href_mismatch")}
    assert soft == {"suspicious"}                        # attack kinds that do not meet the phishing rule

    spec = importlib.util.spec_from_file_location("evaluate", ROOT / "scripts" / "evaluate.py")
    ev = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ev)
    result = ev.evaluate(out, StubLLM(), workspace=tmp_path / "ws")
    assert 0.0 <= result["model_label_exact"] <= 1.0
    assert "evasion_by_category" not in result
