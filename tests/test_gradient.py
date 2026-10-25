"""Tests for the navlayers Gradient color computation."""

import pytest

from mitreattack.navlayers.core.gradient import Gradient


def test_compute_color_at_and_beyond_bounds():
    """Scores at or outside the range map to the first and last colors."""
    gradient = Gradient(colors=["#ff6666", "#ffe766", "#8ec843"], minValue=0, maxValue=100)
    assert gradient.compute_color(-5) == "#ff6666"
    assert gradient.compute_color(0) == "#ff6666"
    assert gradient.compute_color(100) == "#8ec843"
    assert gradient.compute_color(150) == "#8ec843"


@pytest.mark.parametrize(
    "score, expected",
    [(1, "#323232"), (2, "#646464"), (3, "#969696"), (4, "#c8c8c8"), (5, "#d2d2d2"), (7, "#e6e6e6")],
)
def test_compute_color_interpolates_between_stops(score, expected):
    """Intermediate scores are interpolated between the neighbouring stops."""
    gradient = Gradient(colors=["#000000", "#c8c8c8", "#f0f0f0"], minValue=0, maxValue=8)
    assert gradient.compute_color(score) == expected


def test_compute_color_middle_stop():
    """A score at a stop position returns that stop color."""
    gradient = Gradient(colors=["#ff6666", "#ffe766", "#8ec843"], minValue=0, maxValue=4)
    assert gradient.compute_color(2) == "#ffe766"


@pytest.mark.parametrize("score", [9, 10, 10.5, 10.99])
def test_compute_color_range_not_divisible_by_stop_count(score):
    """Ranges that do not divide evenly between the stops must not raise."""
    gradient = Gradient(colors=["#ff0000", "#00ff00", "#0000ff", "#ffffff"], minValue=0, maxValue=11)
    assert gradient.compute_color(score).startswith("#")


def test_compute_color_single_color():
    """A single-color gradient returns that color for every score."""
    gradient = Gradient(colors=["#66b1ff"], minValue=0, maxValue=10)
    assert gradient.compute_color(5) == "#66b1ff"
