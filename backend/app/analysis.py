from datetime import datetime
from typing import Any

import numpy as np
import pandas as pd

from app.schemas import GlucoseContext, METRIC_UNITS, Metric, ReadingAnalysis


def summarize_readings(
    rows: list[dict[str, Any]],
    *,
    astronaut_id: str,
    metric: Metric,
    glucose_context: GlucoseContext | None,
    period_start: datetime,
    period_end: datetime,
) -> ReadingAnalysis:
    frame = pd.DataFrame.from_records(rows, columns=["value", "measured_at"])
    frame["value"] = pd.to_numeric(frame["value"], errors="raise")
    frame["measured_at"] = pd.to_datetime(frame["measured_at"], utc=True, errors="raise")
    frame = frame.sort_values("measured_at", kind="stable")

    values = frame["value"].to_numpy(dtype=np.float64)
    if not np.isfinite(values).all():
        raise ValueError("O histórico contém valores não finitos.")

    elapsed_days = (
        (frame["measured_at"] - frame["measured_at"].iloc[0])
        .dt.total_seconds()
        .to_numpy(dtype=np.float64)
        / 86400
    )
    centered_days = elapsed_days - elapsed_days.mean()
    trend_slope = None
    slope_denominator = float(np.dot(centered_days, centered_days))
    if len(values) > 1 and slope_denominator > 0:
        centered_values = values - values.mean()
        trend_slope = float(
            np.dot(centered_days, centered_values) / slope_denominator
        )

    series = frame["value"]
    latest = frame.iloc[-1]
    return ReadingAnalysis(
        astronaut_id=astronaut_id,
        metric=metric,
        unit=METRIC_UNITS[metric],
        glucose_context=glucose_context,
        period_start=period_start,
        period_end=period_end,
        sample_count=len(values),
        minimum=float(series.min()),
        maximum=float(series.max()),
        mean=float(series.mean()),
        median=float(np.median(values)),
        sample_standard_deviation=(
            float(series.std(ddof=1)) if len(values) > 1 else None
        ),
        latest_value=float(latest["value"]),
        latest_measured_at=latest["measured_at"].to_pydatetime(),
        trend_slope_per_day=trend_slope,
        scope="descriptive_only",
    )
