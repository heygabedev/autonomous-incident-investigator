"""Metadata eligibility checks; never approval, freeze, or promotion decisions."""

from incident_investigator.evaluation.artifacts import retrieval_fingerprint
from incident_investigator.evaluation.models import (
    ArtifactRef,
    CalibrationArtifact,
    CandidateBundle,
    CandidateInput,
    CaseRevision,
    DatasetSnapshot,
    Exposure,
    Invalidation,
    PermittedUse,
    Split,
)
from incident_investigator.evaluation.protocols import ArtifactStore
from incident_investigator.evaluation.registry import RegistryError

USES: dict[Split, PermittedUse] = {
    "dev": "development",
    "calibration": "calibration",
    "sealed_test": "sealed_benchmark",
    "shadow": "shadow",
    "core_regression": "regression",
}


class EligibilityError(RegistryError):
    pass


def require_current(store: ArtifactStore, reference: ArtifactRef) -> None:
    store.resolve(reference)
    for event in store.list_kind("invalidation"):
        invalidation = event.payload
        assert isinstance(invalidation, Invalidation)
        if invalidation.target.digest == reference.digest:
            raise EligibilityError("artifact has a current invalidation")


class RegisteredDatasets:
    def __init__(self, store: ArtifactStore) -> None:
        self.store = store

    def validate(self, reference: ArtifactRef) -> tuple[CaseRevision, ...]:
        require_current(self.store, reference)
        dataset = self.store.resolve(reference).payload
        if not isinstance(dataset, DatasetSnapshot):
            raise EligibilityError("expected dataset snapshot")
        cases: list[CaseRevision] = []
        groups: dict[tuple[str, str], Split] = {}
        for member in dataset.members:
            require_current(self.store, member.case)
            case = self.store.resolve(member.case).payload
            assert isinstance(case, CaseRevision)
            if case.source != "synthetic":
                raise EligibilityError("real-case approval verification is not implemented")
            if case.lifecycle != "verified" or case.data_stage not in ("eligible", "frozen"):
                raise EligibilityError("case is not eligible")
            if USES[member.split] not in case.permitted_uses:
                raise EligibilityError("case does not permit the assigned split use")
            if case.gold_labels.labeling_policy != dataset.labeling_policy:
                raise EligibilityError("labeling policy mismatch")
            for name, value in (
                ("lineage", case.lineage_id),
                ("cluster", case.duplicate_cluster_id),
                ("input", case.candidate_input.input_digest),
            ):
                key = (name, value)
                if key in groups and groups[key] != member.split:
                    raise EligibilityError("related cases cross dataset partitions")
                groups[key] = member.split
            cases.append(case)
        # Exposure to a previous snapshot also taints matching case IDs in successors.
        sealed_ids = {m.case.id for m in dataset.members if m.split == "sealed_test"}
        for event in self.store.list_kind("exposure"):
            exposure = event.payload
            assert isinstance(exposure, Exposure)
            if exposure.disclosure in ("row_level", "development_use") and sealed_ids.intersection(
                exposure.case_ids
            ):
                raise EligibilityError("sealed cases have recorded label exposure")
        return tuple(cases)

    def candidate_inputs(self, snapshot: ArtifactRef) -> tuple[CandidateInput, ...]:
        return tuple(case.candidate_input for case in self.validate(snapshot))


def validate_candidate_links(store: ArtifactStore, reference: ArtifactRef) -> None:
    require_current(store, reference)
    candidate = store.resolve(reference).payload
    if not isinstance(candidate, CandidateBundle):
        raise EligibilityError("expected candidate bundle")
    if candidate.calibration is None:
        return
    require_current(store, candidate.calibration)
    calibration = store.resolve(candidate.calibration).payload
    assert isinstance(calibration, CalibrationArtifact)
    if (
        calibration.retrieval_fingerprint != retrieval_fingerprint(candidate.retrieval)
        or calibration.feature_schema != candidate.retrieval.feature_schema
        or candidate.cause_threshold_ppm < calibration.cause_threshold_ppm
        or candidate.applicability_threshold_ppm < calibration.applicability_threshold_ppm
    ):
        raise EligibilityError("calibration is incompatible with candidate retrieval or thresholds")
    RegisteredDatasets(store).validate(calibration.training_snapshot)
