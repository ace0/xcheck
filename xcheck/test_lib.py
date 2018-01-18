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

def test_canonize():
    """
    Simple known-answer tests
    """
    assert(canonize("Avery","Bales") == "AVERYBALES")
    assert(canonize("Idell", "Leggett") == "IDELLLEGGETT")
    assert(canonize("Farah", "Sharkey") == "FARAHSHARKEY")
    assert(canonize("Alla", "Creamer") == "ALLACREAMER")
    assert(canonize("Lavinia", "Barnhart") == "BARNHARTLAVINIA")
    assert(canonize("Florance", "Arevalo") == "AREVALOFLORANCE")
    assert(canonize("Trinidad", "Langley") == "LANGLEYTRINIDAD")
    assert(canonize("Romona", "Daly") == "DALYROMONA")
    assert(canonize("Elfreda", "Michaud") == "ELFREDAMICHAUD")
    assert(canonize("Tamela", "Garris") == "GARRISTAMELA")

def test_canonizeNonAlpha():
    """
    Tests that canonize handles non-alphanumeric characters
    """
    assert(canonize("Ave3ry","Bales1") == "AVERYBALES")
    assert(canonize("Idell", "Legg`ett") == "IDELLLEGGETT")
    assert(canonize("2Farah", "Sharkey") == "FARAHSHARKEY")
    assert(canonize("Alla", "Creamer4") == "ALLACREAMER")
    assert(canonize("Lavinia\xe2", "Barnhart") == "BARNHARTLAVINIA")

def test_canonizeSpaces():
    """
    Tests that canonize removes whitespace: spaces, tabs, newlines
    """
    assert(canonize("Florance", "  Arevalo") == "AREVALOFLORANCE")
    assert(canonize("Trinidad   ", "Langley\n") == "LANGLEYTRINIDAD")
    assert(canonize("Ro mona", "Da ly") == "DALYROMONA")
    assert(canonize("  El freda ", "    Micha ud     ") == "ELFREDAMICHAUD")
    assert(canonize("  Tamela", "Garris") == "GARRISTAMELA")

def test_canonizePrefixSuffix():
    """
    Tests that canonize always matches reversed names
    """
    assert(canonize("Dr  Avery","Bales") == "AVERYBALES")
    assert(canonize(" Idell", " Leggett III ") == "IDELLLEGGETT")
    assert(canonize("Farah", "Sharkey Jr ") == "FARAHSHARKEY")
    assert(canonize("Mrs Alla", "Creamer") == "ALLACREAMER")
    assert(canonize("Ms. Lavinia ", "Barnhart") == "BARNHARTLAVINIA")
