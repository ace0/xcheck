"""
Manages records in a protected registry. The registry can be queried
or updated with new protected records.
"""
from Crypto.Hash import SHA512
from base64 import urlsafe_b64encode as b64enc
from base64 import urlsafe_b64decode as b64dec
from datetime import date
from datetime import datetime
import csv
import pytest

defaultRegistryFile="./registry"

def processQueryFile(queryfile, registryfile=defaultRegistryFile):
    """
    Processes a queryfile in CSV format. Sample file:
    name1, name2, birthdate
    everspaugh, adam, 1979-10-01
    james, schamber, 1980-12-25
    """
    # Load the registry file
    registry = loadRegistry(registryfile)

    # Track the number of complete and partial matches
    cMatchCount, pMatchCount = (0,0)

    # Process the query file
    with open(queryfile, 'rb') as f:
        # First, verify the header row is as expected as a sanity check
        hdr = f.next()
        if hdr != ["name1", "name2", "birthdate"]:
            raise ValueError("The file '{}' is incorrectly formatted. Header row does not match expected header row.".format(queryfile))

        # Then, process each line as a query
        for (name1, name2, birthdate) in f:
            cMatch, pMatch = query(name1, name2, birthdate)
            cMatchCount += int(cMatch)
            pMatchCount += int(pMatch)

    print "Found {} complete matches, {} partial matches"

def query(name1, name2, birthdate, registry, output=True):
    """
    Performs complete and partial matching of a given entry against a 
    registry. 
    Returns: (isCompleteMatch, isPartialMatch)
    """
    # First, check for a complete match
    if match(name1, name2, birthdate, registry):
        if output:
            print "Complete match for entry: {} {} {}".format(name1, name2, birthdate)
        return (True, False)

    # Next check for partial matches
    for b in partialMatchDates(birthdate):
        if match(name, b, registry):
            if output:
                print "Partial match for entry: {} {} with reported birthday {} but matched to birthdate {}".format(name1, name2, birthdate, b)
            return (False, True)

    # No matching records found
    return (False, False)    

def dateRange(orig, dayOffset=1, yearOffset=10, swapMonthDay=True):
    """
    Iterates through partial match dates
    """
    assert(type(orig) == date)
    # Swap month and day of month if they make a valid date
    if swapMonthDay:
        d = replace(orig, month=orig.day, day=orig.month)
        if d:
            yield d

    # Iterate through day offsets and return all valid dates
    for day in plusminus(orig.day, dayOffset):
        d = replace(orig, day=day)
        if d:
            yield d

    # Iterate through all year offsets and return all valid dates
    for year in plusminus(orig.year, yearOffset):
        d = replace(orig, year=year)
        if d:
            yield d

def plusminus(value, offset):
    """
    Enumerates [value-offset, ..., value+offset] excluding the value.
    """
    for x in range(value-offset, value+offset+1):
        if x != value:
            yield x

def replace(orig, year=None, month=None, day=None):
    """
    Creates a date object if the inputs make a valid date, otherwise
    returns None.
    """
    y = year or orig.year
    m = month or orig.month
    d = day or orig.day

    try:
        return date(y,m,d)
    except ValueError:
        return None

def match(name1, name2, birthdate, registry):
    """
    Checks for a match against the registry
    """
    return protectRecord(name1, name2, birthdate) in registry

def appendRegistry(entries, registryfile=defaultRegistryFile):
    """
    Appends a list of protected records to the registry file
    """
    with open(registryfile, 'at') as f:
        [f.write(entry + "\n") for entry in entries]

def _appendRegistryText(textEntries, registryfile=defaultRegistryFile):
    """
    Processes text entries and appends them to the registry file.
    textEntries = [('name1', 'name2', 'YYYY-mm-dd'), (...), ...]
    """
    # Process the text entries into a list of protected entries
    print textEntries
    protEntries = [protectRecord(n1, n2, dt(bd)) for (n1,n2,bd) in textEntries]
    appendRegistry(protEntries)

def dt(txt, fmt='%Y-%m-%d'):
    """
    Parse a text in YYYY-mm-dd format and returns a datetime.date object if
    it's a valid date. Returns None otherwise.
    """
    return datetime.strptime(txt, fmt).date()

def loadRegistry(registryfile=defaultRegistryFile):
    registry = set()
    with open(registryfile, 'rt') as f:
        [registry.add(x) for x in f.line()]
    return registry

def protectRecord(name1, name2, birthdate):
    """
    Placeholder for record hardening. Replace with the other branch.
    """
    name = canonize(name1, name2)
    assert(type(birthdate) is date)
    secret = "9823nfdskjnsdfgkjanewkrh23qg"
    sha = SHA512.new(data=name)
    sha.update(birthdate.isoformat())
    return b64enc(sha.digest() )

def canonize(name1, name2):
    """
    Remove non-ASCII, non-alphanumeric characters and combine names
    in alphabetical ordering to ensure matching in the face of certain classes
    of typos.
    """
    # Strips non-alphabetical characters and converts to uppercase
    def stripAndUp(txt):
        return ("".join(ch for ch in txt if ch.isalpha())).upper()

    # Strip and uppercase each name, sort to alphabetical order,
    # join and return
    return "".join(sorted([stripAndUp(n) for n in [name1,name2]]))


######
# Tests
#

def test_dateRange():
    d = date(2000, 5, 20)
    expected = set([
        # year +-10
        date(1990, 5, 20), 
        date(1991, 5, 20), 
        date(1992, 5, 20), 
        date(1993, 5, 20), 
        date(1994, 5, 20), 
        date(1995, 5, 20), 
        date(1996, 5, 20), 
        date(1997, 5, 20), 
        date(1998, 5, 20), 
        date(1999, 5, 20), 
        date(2001, 5, 20), 
        date(2002, 5, 20), 
        date(2003, 5, 20), 
        date(2004, 5, 20), 
        date(2005, 5, 20), 
        date(2006, 5, 20), 
        date(2007, 5, 20), 
        date(2008, 5, 20), 
        date(2009, 5, 20), 
        date(2010, 5, 20), 
        date(2001, 5, 20), 
        date(2002, 5, 20), 
        date(2003, 5, 20), 
        date(2004, 5, 20), 
        date(2005, 5, 20), 
        date(2006, 5, 20), 
        date(2007, 5, 20), 
        date(2008, 5, 20), 
        date(2009, 5, 20), 
        date(2010, 5, 20),

        # day +-1
        date(2000, 5, 19),
        date(2000, 5, 21)
    ])
    assert(set([x for x in dateRange(d)]) == expected)

def test_dateRangeSwap():
    founded = date(1848, 6, 5)
    actual = [x for x in dateRange(founded, yearOffset=0, dayOffset=0)]
    assert(actual == [date(1848, 5, 6)])

def test_dateRangeOutOfRange():
    """
    Ensures that dateRange exclude dates that are out of range.
    """
    founded = date(1817, 01, 29)
    expected = set([
            date(1817, 01, 24), 
            date(1817, 01, 25), 
            date(1817, 01, 26), 
            date(1817, 01, 27), 
            date(1817, 01, 28), 
            date(1817, 01, 30), 
            date(1817, 01, 31)
        ])
    actual = set([x for x in dateRange(founded, yearOffset=0, dayOffset=5, 
            swapMonthDay=False)])
    assert(actual == expected)

def test_plusminus():
    """
    Known-answer tests
    """
    assert([x for x in plusminus(5,5)] == [0,1,2,3,4,6,7,8,9,10])

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

def test_canonizeReverse():
    """
    Tests that canonize always matches reversed names
    """
    assert(canonize("Edra", "Gaither") == canonize("Gaither", "Edra"))
    assert(canonize("Toccara", "Wynn") == canonize("Wynn", "Toccara"))
    assert(canonize("Debby", "Heredia") == canonize("Heredia", "Debby"))

def test_dt():
    """
    Known-answer tests
    """
    assert(dt('2000-12-31') == date(2000, 12, 31))
    assert(dt('1955-05-07') == date(1955, 5, 7))

def test_dtBadDate():
    """
    Dates with out-of-range values
    """
    with pytest.raises(ValueError):
        dt('1999-31-12')

    with pytest.raises(ValueError):
        dt('99-12-12')

    with pytest.raises(ValueError):
        dt('1999-31-12')

def test_appendRegistry():
    entries = [
        ("Pok",    "Kuhn", "2000-12-31"),
        ("Kaylene","Mena", "2000-12-31"),
        ("Lourie", "Council", "2000-12-31"),
        ("Sarai",  "Rizzo", "2000-12-31"),
        ("Caroyln","Reddy", "2000-12-31"),
        ("Thad",   "Fife", "2000-12-31"),
        ("Raymond","Slaughter", "2000-12-31"),
        ("Val",    "Brittain", "2000-12-31"),
        ("Tiana",  "Irizarry", "2000-12-31"),
        ("Yajaira","Sheehan", "2000-12-31")
    ]
    _appendRegistryText(entries)
