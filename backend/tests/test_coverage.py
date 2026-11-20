import pytest
from pydantic import ValidationError

from aegentra.coverage import CoverageCheck, CoverageState, assess_coverage


def check(name: str, state: CoverageState, required: bool = True) -> CoverageCheck:
    return CoverageCheck(name=name, state=state, required=required)


def test_missing_checks_are_incomplete() -> None:
    result = assess_coverage(())
    assert result.status == "INCOMPLETE"
    assert result.gaps == ("NO_CHECKS",)


@pytest.mark.parametrize("state", [CoverageState.FAILED, CoverageState.UNKNOWN, CoverageState.UNSUPPORTED])
def test_required_gaps_never_become_reviewable(state: CoverageState) -> None:
    result = assess_coverage((check("javascript-parser", state),))
    assert result.status == "INCOMPLETE"
    assert result.gaps == ("javascript-parser",)


def test_complete_coverage_is_reviewable_not_clean() -> None:
    result = assess_coverage((check("parse", CoverageState.VERIFIED), check("optional", CoverageState.UNSUPPORTED, False)))
    assert result.status == "REVIEWABLE"
    assert result.gaps == ()


def test_required_not_required_is_invalid() -> None:
    with pytest.raises(ValidationError):
        check("parse", CoverageState.NOT_REQUIRED)
