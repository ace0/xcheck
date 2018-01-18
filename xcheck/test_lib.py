"""
Unit tests. Run with `pytest`.
"""
from lib import *
import pytest

def test_scrubPrefixes():
    names = ["Mr. Winnie", "Dr Crypto", "Mr Du-Pont", "Mrs De Marisole", "Paul"]
    expected = ["Winnie", "Crypto", "Du-Pont", "De Marisole", "Paul"]
    actual = [scrubPrefixes(x) for x in names]
    assert(expected == actual)

def test_scrubSuffixes():
    names = ["Rodriguez", "Walters III", "Hinami  Jr. ", "Fausto  Patel MA", "Sanchez-Johnson"]
    expected = ["Rodriguez", "Walters", "Hinami", "Fausto Patel", "Sanchez-Johnson"]
    actual = [scrubSuffixes(x) for x in names]
    assert(expected == actual)
