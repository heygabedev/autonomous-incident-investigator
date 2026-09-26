import hashlib
import json
from pathlib import Path

import pytest
from incident_investigator.security.evidence import (
    RawEvidence,
    ReportClaim,
    publication_bytes,
    sanitize,
)
from incident_investigator.security.policy import authorize
from pydantic import ValidationError

from .test_policy import CONTEXT, policy, request

ROOT = Path(__file__).resolve().parents[4]
DATA = ROOT / "fixtures/evaluation/security/v1"
INPUTS = json.loads((DATA / "inputs.json").read_text())["cases"]
EXPECTED = json.loads((DATA / "expected.json").read_text())


@pytest.mark.parametrize("case", INPUTS, ids=[case["id"] for case in INPUTS])
def test_security_golden(case: dict) -> None:
    expected = EXPECTED[case["id"]]
    kind = case["kind"]
    if kind == "operation":
        outcome = authorize(CONTEXT, request(**case["request"]), policy(), policy(), 0).reason
    elif kind == "schema":
        with pytest.raises(ValidationError):
            request(**case["request"])
        outcome = "schema_denied"
    elif kind == "evidence":
        result = sanitize(
            RawEvidence("000000000000", "eu-central-1", "fixture-1", case["fields"]),
            "000000000000",
            "eu-central-1",
            ("fixture-1",),
        )
        outcome = result.coverage
        if result.evidence is not None:
            assert result.evidence.fields[0].value == expected["value"]
        else:
            assert expected["abstain"]
    else:
        assert kind == "publication"
        record = sanitize(
            RawEvidence("000000000000", "eu-central-1", "fixture-1", {"status": "failed"}),
            "000000000000",
            "eu-central-1",
            ("fixture-1",),
        ).evidence
        assert record is not None
        claim = ReportClaim(
            text="The request failed.",
            evidence_ids=(record.id if case["citation"] == "known" else "invented",),
        )
        try:
            publication_bytes(
                (claim,),
                (record,),
                "000000000000",
                "eu-central-1",
                ("fixture-1",),
                tuple(case["history"]),
            )
            outcome = "allowed"
        except ValueError as exc:
            outcome = str(exc)
    assert outcome == expected["outcome"]


def test_security_dataset_manifest_and_inventory() -> None:
    manifest = json.loads((DATA / "manifest.json").read_text())
    assert manifest["split"] == "dev"
    assert not manifest["promotion_eligible"]
    assert manifest["synthetic"]
    assert len(INPUTS) == manifest["case_count"]
    assert {case["id"] for case in INPUTS} == set(EXPECTED)
    for name in ("inputs.json", "expected.json"):
        assert hashlib.sha256((DATA / name).read_bytes()).hexdigest() == manifest["sha256"][name]
    inventory = json.loads((ROOT / "security/controls.json").read_text())
    assert not inventory["live_enabled"] and not inventory["private_evaluation_enabled"]
    ids = [control["id"] for control in inventory["controls"]]
    assert len(ids) == len(set(ids))
    for control in inventory["controls"]:
        assert control["status"] in {"implemented", "blocked", "deferred"}
        if control["status"] in {"implemented", "blocked"}:
            assert control["tests"]
        for test in control["tests"]:
            assert (ROOT / test).is_file()
