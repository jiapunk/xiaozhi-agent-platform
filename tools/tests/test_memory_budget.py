import pathlib
import sys
import unittest


TOOLS_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

from check_memory_budget import MapError, evaluate_budget, parse_map  # noqa: E402


def fixture(
    *,
    iram_end: int = 0x40380C00,
    heap_end: int = 0x3FC95BC0,
) -> str:
    return f"""
Memory Configuration

Name             Origin             Length             Attributes
iram0_0_seg      0x40374000         0x00057700         xr
dram0_0_seg      0x3fc88000         0x00053700         rw

                0x40378000 _diram_i_start = 0x40378000
                0x40374000 _iram_start = ABSOLUTE (.)
                0x{iram_end:x} _iram_end = ABSOLUTE (.)
                0x{heap_end:x} _heap_low_start = ABSOLUTE (.)
"""


class MemoryBudgetTests(unittest.TestCase):
    def test_parses_shared_esp32s3_layout(self) -> None:
        budget = parse_map(fixture())
        self.assertEqual(budget.dedicated_iram_capacity, 16_384)
        self.assertEqual(budget.iram_span_used, 52_224)
        self.assertEqual(budget.shared_diram_code_used, 35_840)
        self.assertEqual(budget.static_data_used, 20_416)
        self.assertEqual(budget.total_internal_capacity, 358_144)
        self.assertEqual(budget.total_internal_static_used, 72_640)
        self.assertEqual(budget.internal_static_headroom, 285_504)
        self.assertEqual(evaluate_budget(budget, 192 * 1024, 96 * 1024), [])

    def test_reports_each_budget_failure(self) -> None:
        budget = parse_map(fixture(iram_end=0x4038F000, heap_end=0x3FCAD000))
        failures = evaluate_budget(budget, 256 * 1024, 64 * 1024)
        self.assertEqual(len(failures), 2)
        self.assertIn("headroom", failures[0])
        self.assertIn("IRAM", failures[1])

    def test_rejects_missing_or_overlapping_layout(self) -> None:
        with self.assertRaises(MapError):
            parse_map("Memory Configuration\n")
        with self.assertRaisesRegex(MapError, "overlaps"):
            parse_map(fixture(iram_end=0x40390000, heap_end=0x3FC90000))


if __name__ == "__main__":
    unittest.main()
