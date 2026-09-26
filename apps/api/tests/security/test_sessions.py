from concurrent.futures import ThreadPoolExecutor

import pytest
from incident_investigator.security.sessions import AccessError, Sessions


def test_pairing_is_single_use_under_concurrency() -> None:
    sessions = Sessions()
    secret = sessions.issue_pairing()

    def redeem(_: int) -> bool:
        try:
            sessions.redeem(secret)
            return True
        except AccessError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(redeem, range(8))) == 1


def test_pairing_expiry_and_rotation() -> None:
    now = [0.0]
    sessions = Sessions(lambda: now[0])
    first = sessions.issue_pairing()
    second = sessions.issue_pairing()
    with pytest.raises(AccessError):
        sessions.redeem(first)
    now[0] = 300
    with pytest.raises(AccessError):
        sessions.redeem(second)


def test_idle_absolute_expiry_logout_and_restart() -> None:
    now = [0.0]
    sessions = Sessions(lambda: now[0])
    token = sessions.redeem(sessions.issue_pairing())
    now[0] = 1800
    with pytest.raises(AccessError):
        sessions.authenticate(token)
    token = sessions.redeem(sessions.issue_pairing())
    for offset in range(1, 16):
        now[0] = 1800 + offset * 1700
        sessions.authenticate(token)
    now[0] = 1800 + 28_800
    with pytest.raises(AccessError):
        sessions.authenticate(token)
    token = sessions.redeem(sessions.issue_pairing())
    with pytest.raises(AccessError):
        Sessions().authenticate(token)
    sessions.revoke(token)
    with pytest.raises(AccessError):
        sessions.authenticate(token)


def test_rate_limits_and_stream_release() -> None:
    now = [0.0]
    sessions = Sessions(lambda: now[0])
    token = sessions.redeem(sessions.issue_pairing())
    for _ in range(120):
        sessions.authenticate(token)
    with pytest.raises(AccessError) as error:
        sessions.authenticate(token)
    assert error.value.status == 429
    now[0] = 61
    sessions.authenticate(token)
    with (
        sessions.stream(token),
        sessions.stream(token),
        pytest.raises(AccessError),
        sessions.stream(token),
    ):
        pass
    with sessions.stream(token):
        sessions.revoke(token)
        with pytest.raises(AccessError):
            sessions.authenticate(token, touch=False)


def test_pairing_brute_force_is_bounded() -> None:
    sessions = Sessions()
    for _ in range(5):
        with pytest.raises(AccessError) as error:
            sessions.redeem("wrong")
        assert error.value.status == 401
    with pytest.raises(AccessError) as error:
        sessions.redeem("wrong")
    assert error.value.status == 429
