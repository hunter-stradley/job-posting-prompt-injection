"""The benchmark doubles as a regression floor for detector quality."""
import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "run_benchmark",
    os.path.join(os.path.dirname(__file__), os.pardir, "benchmark", "run_benchmark.py"),
)
RB = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(RB)


def test_detection_quality_floor():
    rows = RB.evaluate(RB.load())
    m = RB.metrics(rows)
    assert m["recall"] >= 0.9, m
    assert m["precision"] >= 0.9, m
    assert m["f1"] >= 0.9, m


def test_benign_control_not_flagged():
    rows = RB.evaluate(RB.load())
    benign = [r for r in rows if not r["malicious"]]
    assert benign and all(not r["predicted_positive"] for r in benign)


def test_every_dataset_file_exists():
    rows = RB.evaluate(RB.load())   # would raise FileNotFoundError on a missing fixture
    assert len(rows) >= 15
