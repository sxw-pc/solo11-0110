from datetime import date, datetime, time, timezone


def instant(value):
    """Interpret date-only evidence at UTC day start; require offsets on timestamps."""
    if len(value) == 10:
        return datetime.combine(date.fromisoformat(value), time.min, timezone.utc)
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('timezone_required')
    return parsed.astimezone(timezone.utc)


def utc_day(value):
    return instant(value).date()
