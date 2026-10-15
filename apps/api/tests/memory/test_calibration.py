import pytest
from hypothesis import given
from hypothesis import strategies as st
from incident_investigator.memory.calibration import (
    AdmissionPin,
    Features,
    LabeledPair,
    calibration_metrics,
    fit,
    precision_check,
    predict,
    wilson_lower,
)

PIN = AdmissionPin(
    index_fingerprint="sha256:" + "1" * 64, reasoning_fingerprint="sha256:" + "2" * 64
)
FEATURES = Features(cause_supported=True, resource_exact=True, signal_overlap_ppm=1_000_000)


def pairs(
    split: str, count: int = 100, failures: int = 0, values: Features = FEATURES
) -> tuple[LabeledPair, ...]:
    # Arithmetic test rows, not a claim of real-world sample size or model quality.
    return tuple(
        LabeledPair.model_validate(
            {
                "id": f"{split}-{i}",
                "cluster_id": f"{split}-cluster-{i}",
                "split": split,
                "features": values,
                "same_cause": i >= failures,
                "action_applicable": i >= failures,
            }
        )
        for i in range(count)
    )


def test_calibration_is_fitted_only_on_calibration_and_never_promotion_evidence() -> None:
    training = pairs("calibration")
    calibration = fit(PIN, training)
    assert not calibration.promotion_eligible
    assert predict(calibration, FEATURES).same_cause_ppm == 101_000_000 // 102
    assert calibration == fit(PIN, tuple(reversed(training)))
    with pytest.raises(ValueError, match="wrong_partition"):
        fit(PIN, pairs("held_out"))
    with pytest.raises(ValueError, match="wrong_partition"):
        precision_check(calibration, training)


@pytest.mark.parametrize(
    "count,failures,status",
    [
        (99, 0, "insufficient_evidence"),
        (100, 0, "passed"),
        (100, 5, "failed"),
        (100, 100, "failed"),
    ],
)
def test_held_out_gate_uses_positive_decisions_and_wilson_precision(
    count: int, failures: int, status: str
) -> None:
    result = precision_check(fit(PIN, pairs("calibration")), pairs("held_out", count, failures))
    assert result.status == status
    assert result.positives == count
    assert result.successes == count - failures
    assert not result.promotion_eligible


@pytest.mark.parametrize("field", ["id", "cluster_id"])
def test_training_holdout_overlap_is_rejected(field: str) -> None:
    training, held_out = pairs("calibration"), pairs("held_out")
    collision = held_out[0].model_copy(update={field: getattr(training[0], field)})
    with pytest.raises(ValueError, match="calibration_holdout_leakage"):
        precision_check(fit(PIN, training), (collision, *held_out[1:]))


def test_variants_cannot_inflate_precision_denominator() -> None:
    held_out = pairs("held_out")
    duplicate = held_out[1].model_copy(update={"cluster_id": held_out[0].cluster_id})
    with pytest.raises(ValueError, match="duplicate_independent_unit"):
        precision_check(fit(PIN, pairs("calibration")), (held_out[0], duplicate, *held_out[2:]))


def test_unseen_bins_abstain_and_do_not_count_as_gate_positive() -> None:
    calibration = fit(PIN, pairs("calibration"))
    unseen = FEATURES.model_copy(update={"resource_exact": False})
    prediction = predict(calibration, unseen)
    assert prediction.status == "unseen_bin" and prediction.applicability_ppm == 0
    held_out = pairs("held_out", 200, values=unseen)
    result = precision_check(calibration, held_out)
    assert result.status == "insufficient_evidence" and result.positives == 0


def test_cause_and_applicability_probabilities_are_distinct() -> None:
    training = tuple(
        pair.model_copy(update={"action_applicable": False}) for pair in pairs("calibration")
    )
    probabilities = predict(fit(PIN, training), FEATURES)
    assert probabilities.same_cause_ppm > 900000 and probabilities.applicability_ppm < 100000


def test_ece_and_brier_are_recomputed_from_predictions() -> None:
    assert calibration_metrics([(1_000_000, True), (0, False)]) == (0, 0)
    assert calibration_metrics([(1_000_000, False), (0, True)]) == (1_000_000, 1_000_000)
    assert calibration_metrics([(500000, True), (500000, False)]) == (0, 250000)
    with pytest.raises(ValueError):
        calibration_metrics([])
    with pytest.raises(ValueError):
        calibration_metrics([(1000001, True)])
    with pytest.raises(ValueError):
        calibration_metrics([(True, True)])


@given(st.integers(min_value=1, max_value=10000), st.floats(min_value=0, max_value=1))
def test_wilson_lower_bound_is_bounded_and_monotone(trials: int, fraction: float) -> None:
    successes = int(trials * fraction)
    lower = wilson_lower(successes, trials)
    assert -1e-15 <= lower <= successes / trials + 1e-15
    if successes < trials:
        assert lower <= wilson_lower(successes + 1, trials)


def test_invalid_calibration_and_insufficient_sample_contracts() -> None:
    assert wilson_lower(0, 0) == 0
    assert 0.97 < wilson_lower(100, 100) < 0.98
    with pytest.raises(ValueError):
        wilson_lower(2, 1)
    with pytest.raises(ValueError):
        fit(PIN, ())
    with pytest.raises(ValueError):
        AdmissionPin.model_validate(PIN.model_dump() | {"cause_threshold_ppm": 899999})
    with pytest.raises(ValueError):
        fit(PIN, pairs("calibration") * 2)
    calibration = fit(PIN, pairs("calibration"))
    with pytest.raises(ValueError):
        predict(calibration.model_copy(update={"training_ids": ("fake",)}), FEATURES)
