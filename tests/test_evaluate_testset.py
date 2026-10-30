"""Tests for the APK test-set evaluation script (no real APKs needed)."""
from ml.eval.evaluate_testset import (
    SampleResult,
    action_for,
    binary_metrics,
    evaluate,
    read_labels,
    summarize,
)

POLICY = {"allow_below": 0.25, "warn_below": 0.55, "block_at_or_above": 0.55}


def _r(label, score, group="g"):
    return SampleResult("x", label, group, score, None, action_for(score, POLICY), 0.0)


def test_action_bands():
    assert action_for(0.1, POLICY) == "allow"
    assert action_for(0.25, POLICY) == "warn"
    assert action_for(0.55, POLICY) == "block"


def test_binary_metrics_counts():
    m = binary_metrics(["malicious", "malicious", "benign", "benign"], [True, False, True, False])
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 1, 1)
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["false_positive_rate"] == 0.5


def test_summarize_operating_points_and_auc():
    results = [_r("malicious", 0.9), _r("malicious", 0.4), _r("benign", 0.1), _r("benign", 0.3)]
    s = summarize(results)
    assert s["block_as_positive"]["tp"] == 1 and s["block_as_positive"]["fn"] == 1
    assert s["warn_or_block_as_positive"]["tp"] == 2
    assert s["warn_or_block_as_positive"]["fp"] == 1
    assert s["roc_auc"] == 1.0


def test_errors_are_counted_not_scored(tmp_path):
    (tmp_path / "not_an_apk.apk").write_bytes(b"definitely not a zip")
    (tmp_path / "labels.csv").write_text(
        "path,label,group\nnot_an_apk.apk,benign,junk\nmissing.apk,malicious,junk\n",
        encoding="utf-8")
    assert len(read_labels(tmp_path / "labels.csv")) == 2
    results, _ = evaluate(tmp_path / "labels.csv", "default")
    s = summarize(results)
    assert s["n_listed"] == 2
    assert s["n_errors"] == 2  # one isn't an APK, one can't be read
    errors = sorted(r.error for r in results)
    assert errors[0] == "not an APK" and errors[1].startswith("read: ")


def _write_results(tmp_path, rows, results=None):
    import csv as _csv
    import json as _json

    from ml.eval.summarize_testset import COLUMNS

    results = results or summarize([_r("malicious", 0.9), _r("benign", 0.1)])
    results["policy"] = {"name": "default", **POLICY}
    results["n_listed"] = len(rows)
    (tmp_path / "metrics.json").write_text(_json.dumps(results))
    with (tmp_path / "per_sample.csv").open("w", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(COLUMNS)
        w.writerows(rows)


GOOD_ROWS = [["a" * 64, "malicious", "trojan", 0.9, "critical", "block", "malicious", "1.0", ""],
             ["b" * 64, "benign", "indian_bank", 0.1, "low", "allow", "benign", "1.0", ""]]


def test_summary_written_for_clean_results(tmp_path):
    from ml.eval import summarize_testset as st

    _write_results(tmp_path, GOOD_ROWS)
    metrics, rows = st.load(tmp_path)
    assert st.validate(metrics, rows) == []
    text = st.render(metrics, rows)
    assert "Scored 2 of 2 APKs" in text and "Missed malware (malicious → allow): 0" in text


def test_summary_refuses_paths_and_phone_numbers(tmp_path):
    from ml.eval import summarize_testset as st

    bad = [GOOD_ROWS[0], ["c" * 64, "benign", "from 919876543210", 0.1, "low", "allow", "benign",
                          "1.0", r"read: D:\apk-testset\x.apk"]]
    _write_results(tmp_path, bad)
    problems = st.validate(*st.load(tmp_path))
    assert any("file path" in p for p in problems) and any("phone" in p for p in problems)


def test_evaluate_records_run_info():
    from ml.eval.evaluate_testset import run_info

    info = run_info()
    assert {"git_commit", "androguard", "fuzzy_status", "quark", "date_utc"} <= set(info)
