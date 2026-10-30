"""Verify the pydantic Report model stays in sync with the JSON Schema and that
a minimal report validates against the schema."""
from __future__ import annotations

import json
from pathlib import Path

from schemas.report import InputInfo, InputType, Report

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "report.schema.json"


def test_schema_file_is_valid_json():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["title"] == "APKookies Analysis Report"
    assert schema["properties"]["schema_version"]["const"] == "1.0.0"


def test_minimal_report_roundtrip():
    report = Report(report_id="abc123", input=InputInfo(input_type=InputType.apk))
    dumped = report.model_dump(mode="json")
    assert dumped["schema_version"] == "1.0.0"
    # Roundtrip
    again = Report.model_validate(dumped)
    assert again.report_id == "abc123"


def test_bundle_metadata_roundtrip():
    report = Report(
        report_id="bundle123",
        input=InputInfo(input_type=InputType.apk),
        static_bundle={
            "analysis_status": {"code_intel": {"status": "heuristic"}},
            "coverage": 0.75,
        },
        dynamic_bundle={
            "analysis_status": {"frida": {"status": "unavailable"}},
            "coverage": 0.35,
        },
    )
    dumped = report.model_dump(mode="json")
    assert dumped["static_bundle"]["analysis_status"]["code_intel"]["status"] == "heuristic"
    assert dumped["dynamic_bundle"]["analysis_status"]["frida"]["status"] == "unavailable"


def test_report_matches_schema_if_jsonschema_installed():
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return  # optional; skip when jsonschema not present
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    report = Report(report_id="abc123", input=InputInfo(input_type=InputType.apk))
    jsonschema.validate(report.model_dump(mode="json"), schema)


def test_hashes_fields_match_json_schema():
    from schemas.report import Hashes

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert set(schema["properties"]["hashes"]["properties"]) == set(Hashes.model_fields)


def test_api_usage_fields_match_json_schema():
    from schemas.report import ApiUsage

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    items = schema["properties"]["static_findings"]["properties"]["api_usage"]["items"]
    assert set(items["properties"]) == set(ApiUsage.model_fields)


def test_anti_analysis_fields_match_json_schema():
    from schemas.report import AntiAnalysis

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    items = schema["properties"]["static_findings"]["properties"]["anti_analysis"]["items"]
    assert set(items["properties"]) == set(AntiAnalysis.model_fields)


def test_signing_fields_match_json_schema():
    from schemas.report import Signing

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    props = schema["properties"]["static_findings"]["properties"]["signing"]["properties"]
    assert set(props) == set(Signing.model_fields)


def test_risk_fields_match_json_schema():
    from schemas.report import Risk, RuleHit, ScoreStep

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    risk = schema["properties"]["risk"]["properties"]
    assert set(risk) == set(Risk.model_fields)
    assert set(risk["breakdown"]["items"]["properties"]) == set(ScoreStep.model_fields)
    assert set(risk["rules_triggered"]["items"]["properties"]) == set(RuleHit.model_fields)


def test_verdict_fields_match_json_schema():
    from schemas.report import Verdict

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert set(schema["properties"]["verdict"]["properties"]) == set(Verdict.model_fields)
