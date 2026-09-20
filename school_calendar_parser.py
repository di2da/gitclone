"""Read-only parser for the 2026-27 school calendar Google Sheet.

The source sheet is a human-maintained timetable, not a normalized table.  This
module intentionally returns a preview structure only; it never writes to the
database.  Ambiguous source rows are surfaced for human review instead of being
silently guessed.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from collections import Counter
from datetime import date
from typing import Any


WEEKDAY_NAMES = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"]
REVIEW_ROW_PREFIXES = ("活動可用的人", "時間：", "時間:", "暑期班")


def _clean(value: Any) -> str:
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()


def _cell(row: list[str], index: int) -> str:
    return _clean(row[index]) if index < len(row) else ""


def _academic_years(school_year: str) -> tuple[int, int]:
    match = re.search(r"(20\d{2})\D+(\d{2,4})", school_year or "")
    if not match:
        return 2026, 2027
    start = int(match.group(1))
    raw_end = int(match.group(2))
    end = raw_end if raw_end >= 1000 else (start // 100) * 100 + raw_end
    return start, end


def _weekday_heading(value: str) -> str:
    compact = re.sub(r"\s+", "", value or "")
    for weekday in WEEKDAY_NAMES:
        if compact == weekday:
            return weekday
    return ""


def _weekday_from_header(value: str) -> str:
    compact = re.sub(r"\s+", "", value or "")
    for weekday in WEEKDAY_NAMES:
        if weekday in compact:
            return weekday
    return ""


def _first_line(value: str) -> str:
    return next((line.strip() for line in _clean(value).splitlines() if line.strip()), "")


def _teacher_names(value: str) -> list[str]:
    names: list[str] = []
    for raw_line in _clean(value).splitlines():
        line = raw_line.strip()
        if not line or re.search(r"(?i)\bTEL\b|電話|(?:\+?852\D*)?\d{4}\D*\d{4}", line):
            continue
        line = re.sub(r"^(?:導師|主教|助教)\s*[：:]\s*", "", line).strip()
        for part in re.split(r"[/、,，]", line):
            name = part.strip()
            if name and name not in names:
                names.append(name)
    return names


def _normalize_time_range(value: str) -> tuple[str, str]:
    text = _clean(value).replace("：", ":").replace("－", "-").replace("–", "-").replace("—", "-")
    match = re.search(
        r"(?<!\d)(\d{1,2})(?::?(\d{2}))\s*(?:-|至|~|～)\s*(\d{1,2})(?::?(\d{2}))(?!\d)",
        text,
    )
    if not match:
        return "", ""
    h1, m1, h2, m2 = (int(part) for part in match.groups())
    if h1 > 23 or h2 > 23 or m1 > 59 or m2 > 59:
        return "", ""
    return f"{h1:02d}:{m1:02d}", f"{h2:02d}:{m2:02d}"


def _session_type(text: str) -> str:
    value = _clean(text)
    for keyword, label in [
        ("選拔", "選拔"),
        ("綵排", "綵排"),
        ("彩排", "綵排"),
        ("表演", "表演"),
        ("補課", "補課"),
        ("後備", "後備日"),
        ("拍攝", "拍攝"),
    ]:
        if keyword in value:
            return label
    return "課堂"


def _extract_dates(schedule_text: str, school_year: str) -> tuple[list[dict[str, Any]], list[str]]:
    start_year, end_year = _academic_years(school_year)
    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    seen: set[str] = set()

    for raw_line in _clean(schedule_text).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        explicit_year_match = re.search(r"(20\d{2})\s*年", line)
        explicit_year = int(explicit_year_match.group(1)) if explicit_year_match else None
        month_matches = list(re.finditer(r"(?<!\d)(1[0-2]|0?[1-9])\s*月", line))
        for index, match in enumerate(month_matches):
            month = int(match.group(1))
            segment_end = month_matches[index + 1].start() if index + 1 < len(month_matches) else len(line)
            segment = line[match.end() : segment_end]
            # Weekday annotations and times must not become day numbers.
            segment = re.sub(r"[（(][^）)]*(?:星期|週|周)[^）)]*[）)]", "", segment)
            segment = segment.split("日", 1)[0]
            days = [int(value) for value in re.findall(r"(?<!\d)(\d{1,2})(?!\d)", segment)]
            if not days:
                continue
            year = explicit_year or (start_year if month >= 9 else end_year)
            for day in days:
                try:
                    parsed = date(year, month, day)
                except ValueError:
                    warnings.append(f"無效日期：{year:04d}-{month:02d}-{day:02d}")
                    continue
                iso_date = parsed.isoformat()
                if iso_date in seen:
                    continue
                seen.add(iso_date)
                events.append(
                    {
                        "session_date": iso_date,
                        "weekday": WEEKDAY_NAMES[parsed.weekday()],
                        "session_type": _session_type(line),
                        "source_line": line,
                    }
                )
    events.sort(key=lambda event: event["session_date"])
    return events, warnings


def _expected_total(row: list[str]) -> int | None:
    value = _cell(row, 8)
    match = re.search(r"\d+", value.replace(",", ""))
    if not match:
        return None
    result = int(match.group(0))
    return result if result > 0 else None


def parse_school_calendar_csv(
    csv_text: str,
    school_year: str = "2026-27",
    max_source_row: int = 75,
) -> dict[str, Any]:
    """Return a non-mutating import preview for the human-formatted timetable."""

    rows = list(csv.reader(io.StringIO(csv_text or "")))
    if not rows:
        return {
            "school_year": school_year,
            "max_source_row": max_source_row,
            "programs": [],
            "summary": {"source_rows": 0, "included_rows": 0, "excluded_after_cutoff": 0},
        }

    current_weekday = _weekday_from_header(_cell(rows[0], 0))
    previous_schedule_by_school: dict[str, str] = {}
    programs: list[dict[str, Any]] = []
    excluded_after_cutoff = 0
    blank_rows = 0
    heading_rows = 0

    for source_row, raw_row in enumerate(rows[1:], start=2):
        if source_row > max_source_row:
            if any(_clean(value) for value in raw_row):
                excluded_after_cutoff += 1
            continue
        row = [_clean(value) for value in raw_row]
        if not any(row):
            blank_rows += 1
            continue
        heading = _weekday_heading(_cell(row, 0))
        if heading:
            current_weekday = heading
            heading_rows += 1
            continue

        school_raw = _cell(row, 0)
        school_name = _first_line(school_raw)
        program_name = _cell(row, 1)
        schedule_text = _cell(row, 2)
        time_text = _cell(row, 3)
        duration_text = _cell(row, 4)
        teacher_names = _teacher_names(_cell(row, 5))
        warnings: list[str] = []
        inherited = False

        if schedule_text == "同上":
            inherited_text = previous_schedule_by_school.get(school_name, "")
            if inherited_text:
                schedule_text = inherited_text
                inherited = True
                warnings.append("日期由同校上一行「同上」繼承，需人工覆核")
            else:
                warnings.append("「同上」找不到同校上一行日期")
        elif schedule_text and school_name:
            previous_schedule_by_school[school_name] = schedule_text

        events, date_warnings = _extract_dates(schedule_text, school_year)
        warnings.extend(date_warnings)
        start_time, end_time = _normalize_time_range(time_text)
        expected_total = _expected_total(row)

        if not school_name:
            warnings.append("缺少校名")
        if school_name.startswith(REVIEW_ROW_PREFIXES) or school_name.startswith(("康城：", "女青：")):
            warnings.append("此行似乎是備忘／活動資料，不應自動當作學校班別")
        if not events:
            warnings.append("未能解析實際日期")
        if not start_time or not end_time:
            warnings.append("未有可用的標準上課時間")
        if not teacher_names:
            warnings.append("未有可比對的負責導師")
        if expected_total is not None and expected_total != len(events):
            warnings.append(f"總堂數欄為{expected_total}，但解析到{len(events)}個日期")
        section_mismatches = [event for event in events if current_weekday and event["weekday"] != current_weekday]
        if section_mismatches:
            warnings.append(f"有{len(section_mismatches)}個日期與所屬星期分段不一致，可能是特別課／表演／改期")
        if re.search(r"改為|時間容後|未定|後備日|表演日|綵排日|彩排日", schedule_text):
            warnings.append("含特別時間／待定／後備／表演資訊，需人工覆核")

        status = "ready"
        if not events or not school_name:
            status = "incomplete"
        elif warnings:
            status = "review"

        source_key = hashlib.sha256(
            f"{school_year}|{source_row}|{school_name}|{program_name}|{schedule_text}|{time_text}".encode("utf-8")
        ).hexdigest()[:16]
        programs.append(
            {
                "source_row": source_row,
                "source_key": source_key,
                "school_year": school_year,
                "weekday": current_weekday,
                "school_name": school_name,
                "school_raw": school_raw,
                "program_name": program_name,
                "schedule_text": schedule_text,
                "time_text": time_text,
                "start_time": start_time,
                "end_time": end_time,
                "duration_text": duration_text,
                "teacher_names": teacher_names,
                "expected_total": expected_total,
                "parsed_session_count": len(events),
                "events": events,
                "warnings": warnings,
                "status": status,
                "inherited_same_as_above": inherited,
            }
        )

    status_counts = Counter(program["status"] for program in programs)
    warning_counts = Counter(warning for program in programs for warning in program["warnings"])
    session_count = sum(program["parsed_session_count"] for program in programs)
    return {
        "school_year": school_year,
        "max_source_row": max_source_row,
        "programs": programs,
        "summary": {
            "source_rows": len(rows),
            "included_rows": len(programs),
            "excluded_after_cutoff": excluded_after_cutoff,
            "blank_rows": blank_rows,
            "heading_rows": heading_rows,
            "ready_rows": status_counts.get("ready", 0),
            "review_rows": status_counts.get("review", 0),
            "incomplete_rows": status_counts.get("incomplete", 0),
            "parsed_sessions": session_count,
            "warning_count": sum(warning_counts.values()),
            "warning_types": dict(warning_counts.most_common()),
        },
    }

