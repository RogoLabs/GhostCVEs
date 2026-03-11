"""Test datetime timezone compatibility fix."""
from datetime import datetime, timezone, timedelta
import pytest


def test_timezone_aware_subtraction():
    """Verify timezone-aware datetime subtraction works correctly."""
    # Create timezone-aware datetime (like from database)
    discovered_at = datetime.now(timezone.utc) - timedelta(hours=12)

    # Current time (timezone-aware)
    now = datetime.now(timezone.utc)

    # This should work without TypeError
    age = now - discovered_at

    # Verify the calculation makes sense
    assert age.total_seconds() > 0
    assert age.total_seconds() < 24 * 3600  # Less than 24 hours


def test_timezone_naive_fails():
    """Demonstrate that timezone-naive subtraction fails."""
    # Create timezone-aware datetime
    discovered_at = datetime.now(timezone.utc)

    # Create timezone-naive datetime (the old way)
    naive_now = datetime.utcnow()

    # This should raise TypeError
    with pytest.raises(TypeError, match="can't subtract offset-naive and offset-aware datetimes"):
        age = naive_now - discovered_at
