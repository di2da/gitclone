import csv
import io
import unittest

from school_calendar_parser import parse_school_calendar_csv


def build_csv(rows):
    output = io.StringIO()
    csv.writer(output).writerows(rows)
    return output.getvalue()


class SchoolCalendarParserTests(unittest.TestCase):
    def test_parses_dates_and_inherits_same_as_above(self):
        text = build_csv(
            [
                ["校名 星期一", "", "", "時間", "時長", "負責導師", "", "", "總堂數"],
                ["示範小學", "初班", "2026年\n10月5、12日\n2027年\n1月4日", "15:30-17:00", "90mins", "Teacher A\nTEL: 1234 5678", "", "", "3"],
                ["示範小學", "高班", "同上", "17:00-18:00", "60mins", "Teacher B", "", "", "3"],
            ]
        )
        result = parse_school_calendar_csv(text, school_year="2026-27", max_source_row=75)
        self.assertEqual(result["summary"]["parsed_sessions"], 6)
        self.assertEqual(result["programs"][0]["teacher_names"], ["Teacher A"])
        self.assertEqual(result["programs"][0]["start_time"], "15:30")
        self.assertEqual(result["programs"][0]["events"][2]["session_date"], "2027-01-04")
        self.assertTrue(result["programs"][1]["inherited_same_as_above"])

    def test_marks_weekday_exception_for_special_date(self):
        text = build_csv(
            [
                ["校名 星期三", "", "", "時間", "時長", "負責導師"],
                ["示範小學", "校隊", "10月7日\n12月18日（星期五）", "15:00-16:00", "", "Teacher A"],
            ]
        )
        result = parse_school_calendar_csv(text, school_year="2026-27")
        warnings = result["programs"][0]["warnings"]
        self.assertTrue(any("星期分段不一致" in warning for warning in warnings))

    def test_excludes_source_row_76_and_below(self):
        rows = [["校名 星期一", "", "", "時間", "時長", "負責導師"]]
        for source_row in range(2, 76):
            rows.append([f"學校{source_row}", "班別", "10月5日", "15:00-16:00", "", "Teacher"])
        rows.append(["不應匯入學校", "班別", "10月6日", "15:00-16:00", "", "Teacher"])
        text = build_csv(rows)
        result = parse_school_calendar_csv(text, max_source_row=75)
        self.assertEqual(len(result["programs"]), 74)
        self.assertEqual(result["summary"]["excluded_after_cutoff"], 1)
        self.assertNotIn("不應匯入學校", [program["school_name"] for program in result["programs"]])


if __name__ == "__main__":
    unittest.main()

