"""Development-only histogram calibration and independent precision checks.

Public synthetic labels cannot qualify a production calibration or promotion.
Unseen feature bins abstain; no similarity-to-probability conversion is assumed.
"""

import math
from collections import defaultdict
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from incident_investigator.evaluation.models import Contract, Digest, Identifier, Probability
from incident_investigator.memory.contracts import MemoryCase, Query, digest
from incident_investigator.memory.retrieval import hypotheses


class AdmissionPin(Contract):
    index_fingerprint: Digest
    reasoning_fingerprint: Digest
    feature_schema: Literal["history-features-v1"] = "history-features-v1"
    policy: Literal["historical-admission-v1"] = "historical-admission-v1"
    cause_threshold_ppm: Annotated[int, Field(ge=900_000, le=1_000_000)] = 900_000
    applicability_threshold_ppm: Annotated[int, Field(ge=900_000, le=1_000_000)] = 900_000


class Features(Contract):
    cause_supported: bool
    resource_exact: bool
    signal_overlap_ppm: Probability

    def bin_key(self) -> str:
        overlap = self.signal_overlap_ppm // 100000
        return f"{int(self.cause_supported)}-{int(self.resource_exact)}-{overlap}"


def features(query: Query, case: MemoryCase) -> Features:
    current = {item.signal for item in query.incident.observations}
    previous = {item.signal for item in case.incident.observations}
    supported = [item for item in hypotheses(query) if item.verdict == "supported"]
    return Features(
        cause_supported=len(supported) == 1 and supported[0].cause == case.verified_cause,
        resource_exact=query.incident.resource == case.incident.resource,
        signal_overlap_ppm=len(current & previous) * 1_000_000 // max(len(current | previous), 1),
    )


class LabeledPair(Contract):
    source: Literal["synthetic_development"] = "synthetic_development"
    id: Identifier
    # One independent base-incident cluster per row. Related variants must use
    # the same cluster ID and cannot inflate a training or precision denominator.
    cluster_id: Identifier
    split: Literal["calibration", "held_out"]
    features: Features
    same_cause: bool
    action_applicable: bool

    @model_validator(mode="after")
    def check_labels(self) -> Self:
        if self.action_applicable and not self.same_cause:
            raise ValueError("inconsistent_labels")
        return self


class Bin(Contract):
    key: Identifier
    samples: Annotated[int, Field(ge=1, le=10000)]
    cause_successes: Annotated[int, Field(ge=0, le=10000)]
    applicability_successes: Annotated[int, Field(ge=0, le=10000)]

    @model_validator(mode="after")
    def check_counts(self) -> Self:
        if not self.applicability_successes <= self.cause_successes <= self.samples:
            raise ValueError("invalid_bin_counts")
        return self


class Calibration(Contract):
    version: Literal["histogram-laplace-v1"] = "histogram-laplace-v1"
    source: Literal["synthetic_development"] = "synthetic_development"
    promotion_eligible: Literal[False] = False
    pin: AdmissionPin
    training_digest: Digest
    training_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=10000)]
    training_clusters: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=10000)]
    bins: Annotated[tuple[Bin, ...], Field(min_length=1, max_length=44)]

    @model_validator(mode="after")
    def check_identity(self) -> Self:
        if len(self.training_ids) != len(self.training_clusters):
            raise ValueError("training_counts")
        if len(set(self.training_ids)) != len(self.training_ids) or len(
            set(self.training_clusters)
        ) != len(self.training_clusters):
            raise ValueError("duplicate_training_units")
        if len({item.key for item in self.bins}) != len(self.bins):
            raise ValueError("duplicate_bin")
        if sum(item.samples for item in self.bins) != len(self.training_ids):
            raise ValueError("training_denominator")
        return self


class Probabilities(Contract):
    same_cause_ppm: Probability
    applicability_ppm: Probability
    status: Literal["estimated", "unseen_bin"]


class PrecisionResult(Contract):
    status: Literal["passed", "failed", "insufficient_evidence"]
    positives: Annotated[int, Field(ge=0, le=10000)]
    successes: Annotated[int, Field(ge=0, le=10000)]
    wilson_lower_ppm: Probability
    calibration_digest: Digest
    held_out_digest: Digest
    cause_ece_ppm: Probability
    applicability_ece_ppm: Probability
    cause_brier_ppm: Probability
    applicability_brier_ppm: Probability
    promotion_eligible: Literal[False] = False


def _validate_pairs(pairs: tuple[LabeledPair, ...], split: str) -> tuple[LabeledPair, ...]:
    if not 1 <= len(pairs) <= 10000:
        raise ValueError("pair_limit")
    pairs = tuple(LabeledPair.model_validate_json(item.model_dump_json()) for item in pairs)
    if any(item.split != split for item in pairs):
        raise ValueError("wrong_partition")
    if len({item.id for item in pairs}) != len(pairs) or len(
        {item.cluster_id for item in pairs}
    ) != len(pairs):
        raise ValueError("duplicate_independent_unit")
    return tuple(sorted(pairs, key=lambda item: item.id))


def _pairs_digest(pairs: tuple[LabeledPair, ...]) -> str:
    # Hash a bounded manifest of row digests rather than unbounded joined payloads.
    from incident_investigator.evaluation.canonical import content_digest

    return content_digest([digest(item) for item in pairs])


def fit(pin: AdmissionPin, pairs: tuple[LabeledPair, ...]) -> Calibration:
    pin = AdmissionPin.model_validate_json(pin.model_dump_json())
    pairs = _validate_pairs(pairs, "calibration")
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for pair in pairs:
        row = counts[pair.features.bin_key()]
        row[0] += 1
        row[1] += int(pair.same_cause)
        row[2] += int(pair.action_applicable)
    return Calibration(
        pin=pin,
        training_digest=_pairs_digest(pairs),
        training_ids=tuple(item.id for item in pairs),
        training_clusters=tuple(item.cluster_id for item in pairs),
        bins=tuple(
            Bin(key=key, samples=n, cause_successes=c, applicability_successes=a)
            for key, (n, c, a) in sorted(counts.items())
        ),
    )


def predict(calibration: Calibration, values: Features) -> Probabilities:
    calibration = Calibration.model_validate_json(calibration.model_dump_json())
    values = Features.model_validate_json(values.model_dump_json())
    row = next((row for row in calibration.bins if row.key == values.bin_key()), None)
    if row is None:
        return Probabilities(same_cause_ppm=0, applicability_ppm=0, status="unseen_bin")
    return Probabilities(
        same_cause_ppm=(row.cause_successes + 1) * 1_000_000 // (row.samples + 2),
        applicability_ppm=(row.applicability_successes + 1) * 1_000_000 // (row.samples + 2),
        status="estimated",
    )


def wilson_lower(successes: int, trials: int) -> float:
    if type(successes) is not int or type(trials) is not int or not 0 <= successes <= trials:
        raise ValueError("invalid_trials")
    if trials == 0:
        return 0.0
    z = 1.6448536269514722  # One-sided 95%, not a two-sided 95% interval.
    p = successes / trials
    return (
        p
        + z * z / (2 * trials)
        - z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))
    ) / (1 + z * z / trials)


def precision_check(calibration: Calibration, pairs: tuple[LabeledPair, ...]) -> PrecisionResult:
    calibration = Calibration.model_validate_json(calibration.model_dump_json())
    pairs = _validate_pairs(pairs, "held_out")
    if set(calibration.training_ids).intersection(item.id for item in pairs) or set(
        calibration.training_clusters
    ).intersection(item.cluster_id for item in pairs):
        raise ValueError("calibration_holdout_leakage")
    positives = successes = 0
    cause_scores: list[tuple[int, bool]] = []
    action_scores: list[tuple[int, bool]] = []
    for pair in pairs:
        prediction = predict(calibration, pair.features)
        cause_scores.append((prediction.same_cause_ppm, pair.same_cause))
        action_scores.append((prediction.applicability_ppm, pair.action_applicable))
        if (
            pair.features.cause_supported
            and prediction.same_cause_ppm >= calibration.pin.cause_threshold_ppm
            and prediction.applicability_ppm >= calibration.pin.applicability_threshold_ppm
        ):
            positives += 1
            successes += int(pair.same_cause and pair.action_applicable)
    lower = max(0, math.floor(wilson_lower(successes, positives) * 1_000_000))
    cause_ece, cause_brier = calibration_metrics(cause_scores)
    action_ece, action_brier = calibration_metrics(action_scores)
    passes = (
        lower >= 950000
        and max(cause_ece, action_ece) <= 50000
        and max(cause_brier, action_brier) <= 100000
    )
    return PrecisionResult(
        status="insufficient_evidence" if positives < 100 else "passed" if passes else "failed",
        positives=positives,
        successes=successes,
        wilson_lower_ppm=lower,
        calibration_digest=digest(calibration),
        held_out_digest=_pairs_digest(pairs),
        cause_ece_ppm=cause_ece,
        applicability_ece_ppm=action_ece,
        cause_brier_ppm=cause_brier,
        applicability_brier_ppm=action_brier,
    )


def calibration_metrics(scores: list[tuple[int, bool]]) -> tuple[int, int]:
    """Ten fixed equal-width bins; integer ppm with conservative rounding up."""
    if not scores or len(scores) > 10000:
        raise ValueError("metric_denominator")
    buckets: dict[int, int] = defaultdict(int)
    squared = 0
    for probability, actual in scores:
        if (
            type(probability) is not int
            or not 0 <= probability <= 1_000_000
            or type(actual) is not bool
        ):
            raise ValueError("invalid_probability_or_label")
        error = probability - int(actual) * 1_000_000
        buckets[min(9, probability // 100000)] += error
        squared += error * error
    count = len(scores)
    ece = (sum(abs(error) for error in buckets.values()) + count - 1) // count
    brier = (squared + count * 1_000_000 - 1) // (count * 1_000_000)
    return ece, brier
