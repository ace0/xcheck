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

# first_names = []
# for i in names:
#     new_name = i.split()
#     if new_name[0] in prefixes:
#         first_names.append(new_name[1:])
#     else:
#         first_names.append(new_name[0:])
# print(first_names)



# Script to clean the suffixes:

# names = ["Rodriguez", "Walters III", "Hinami Jr.", "Fausto  Patel MA", "Sanchez-Johnson"]
# suffixes = ["I", "II", "III", "IV", "Jr.", "Sr.", "Jr", "Sr", "MA", "MD", "1st", "2nd", "3rd"]
# last_names = []
# for i in names:
#     new_name = i.split()
#     if new_name[-1] in suffixes:
#         last_names.append(new_name[:-1])
#     else:
#         last_names.append(new_name[0:])
# print(last_names)