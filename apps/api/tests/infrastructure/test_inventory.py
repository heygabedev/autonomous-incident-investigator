import json
import re
from pathlib import Path

import yaml
from incident_investigator.infrastructure.plans import REVIEW_TYPES, RULES, TERRAFORM_VERSION

ROOT = Path(__file__).resolve().parents[4]
INFRA = ROOT / "infra/aws"


def test_inventory_never_claims_live_enablement_or_recovery_results():
    inventory = json.loads((ROOT / "security/aws-infrastructure.json").read_text())
    assert inventory["live_enabled"] is False
    assert inventory["private_evaluation_enabled"] is False
    assert inventory["deployment_authorized"] is False
    assert inventory["verification"]["achieved_rto_rpo"] is None
    assert inventory["terraform_version"] == TERRAFORM_VERSION
    versions = (INFRA / "versions.tf").read_text()
    assert f'required_version = "= {TERRAFORM_VERSION}"' in versions
    assert f'version = "= {inventory["aws_provider_version"]}"' in versions
    lock = (INFRA / ".terraform.lock.hcl").read_text()
    assert f'version     = "{inventory["aws_provider_version"]}"' in lock


def test_plan_guard_tracks_every_declared_resource_type():
    source = "\n".join(path.read_text() for path in INFRA.glob("*.tf"))
    declared = set(re.findall(r'^resource "([^"]+)"', source, re.MULTILINE))
    assert declared == RULES.keys() | REVIEW_TYPES
    assert "backend " not in source  # No unreviewed state backend is silently bootstrapped.
    assert "provisioner " not in source


def test_test_files_cannot_select_an_unmocked_provider():
    # This repository deliberately uses one fixed local test module and no alternate providers.
    # Linux CI additionally removes external network access while Terraform executes tests.
    files = list((INFRA / "tests").glob("*.tftest.*"))
    assert files
    for path in files:
        assert path.suffix == ".hcl"
        source = path.read_text()
        assert re.findall(r'^mock_provider "([^"]+)"', source, re.MULTILINE) == ["aws"]
        assert not re.search(r'\b(?:provider|module|providers)\s*(?:"|\{|=)', source)


def test_infrastructure_ci_has_no_deployment_or_oidc_permissions():
    workflow = yaml.safe_load((ROOT / ".github/workflows/infrastructure.yml").read_text())
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["terraform-contracts"]
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "windows-latest"]
    assert "permissions" not in job
    commands = "\n".join(step.get("run", "") for step in job["steps"])
    assert "unshare --net" in commands
    assert "-lockfile=readonly" in commands
    assert "-backend=false" in commands
    assert not re.search(r"\b(?:apply|destroy|plan)\b", commands)
    assert "aws-actions" not in str(workflow)
    for step in job["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w/-]+@[a-f0-9]{40}", step["uses"])


def test_inventory_references_real_contract_tests():
    inventory = json.loads((ROOT / "security/controls.json").read_text())
    control = next(c for c in inventory["controls"] if c["id"] == "aws-infrastructure-contracts")
    assert control["status"] == "implemented"
    for path in control["tests"]:
        assert (ROOT / path).is_file()
