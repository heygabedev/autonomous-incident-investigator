import json
from pathlib import Path

import pytest
from incident_investigator.evaluation.golden import IncidentInput, load_input
from incident_investigator.workflow.contracts import ReplayInput
from incident_investigator.workflow.replay import prepare

ROOT = Path(__file__).resolve().parents[4]
GOLDEN = ROOT / "fixtures/evaluation/golden/v1"
MEMBERS = json.loads((GOLDEN / "manifest.json").read_text())["members"]


def incident(index: int = 0) -> IncidentInput:
    member = MEMBERS[index]
    return load_input(GOLDEN / "inputs", member["case_id"], member["input_digest"])


@pytest.mark.parametrize(
    "index,count,gaps", [(0, 3, 0), (1, 3, 0), (2, 3, 0), (3, 3, 0), (4, 1, 2), (5, 3, 1)]
)
def test_prepare_known_public_inputs(index: int, count: int, gaps: int) -> None:
    result = prepare(incident(index))
    assert len(result.observations) == count and len(result.gaps) == gaps
    assert "text" not in result.model_dump_json()
    assert "Ignore all previous instructions" not in result.model_dump_json()
    assert ReplayInput.model_validate_json(result.model_dump_json()) == result


def test_appended_instructions_and_secrets_are_omitted() -> None:
    value = incident()
    poisoned = value.evidence[0].model_copy(
        update={"text": value.evidence[0].text + " password=private"}
    )
    result = prepare(value.model_copy(update={"evidence": (poisoned, *value.evidence[1:])}))
    assert result.gaps[0].reason == "unsupported_payload"
    assert "private" not in result.model_dump_json()


def test_scope_signal_and_time_forgery_rejected() -> None:
    value = prepare(incident())
    for change in (
        {"resource": "other"},
        {"signal": "startup_healthy"},
        {"observed_at": "2026-01-01T00:00:00Z"},
    ):
        payload = value.model_dump(mode="json")
        if "resource" in change:
            payload["observations"][0]["evidence"].update(change)
        else:
            payload["observations"][0].update(change)
        with pytest.raises(ValueError):
            ReplayInput.model_validate_json(json.dumps(payload))


def test_renaming_case_does_not_select_a_diagnosis() -> None:
    value = incident()
    assert (
        prepare(value).observations
        == prepare(value.model_copy(update={"case_id": "unseen-case"})).observations
    )
