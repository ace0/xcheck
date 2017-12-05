"""
Manages records in a protected registry. The registry can be queried
or updated with new protected records.
"""
from Crypto.Hash import SHA512
from base64 import urlsafe_b64encode as b64enc
from base64 import urlsafe_b64decode as b64dec
from datetime import date
from datetime import datetime
from tempfile import NamedTemporaryFile
from crypto import protectRecord, publicKeyDecrypt
import csv, pytest

defaultRegistryFile = "./registry"
defaultPubkey = "./registry-public.pem"


def processQueryFile(queryJeefile, pubkey, registry):
    """
    Processes an encrypted query.jee once pubkey and registry have been loaded
    into memory.
    """

    # Track the number of complete and partial matches
    cMatchCount, pMatchCount = (0,0)

    # Process the query file
    for (name1, name2, birthdate) in enumerateCsv(queryJeefile):
        cMatch, pMatch = query(registry, name1, name2, birthdate)
        cMatchCount += int(cMatch)
        pMatchCount += int(pMatch)

    if cMatchCount + pMatchCount == 0:
        print "Found no complete or partial matches"
    return cMatchCount, pMatchCount

def processRegistryUpdateFile(updatefile, registryfile=defaultRegistryFile):
    """
    Processes an update file in CSV format and appends protected records
    to the registry file.
    """
    # Read the update CSV and protect individual entries
    entries = [protectRecord(n1,n2,bd) for (n1,n2,bd) in enumerateCsv(updatefile)]
    appendRegistry(entries, registryfile)
    return len(entries)

def enumerateCsv(queryfile):
    """
    Reads and validates a query.csv. Requires a well-formed header row
    and converts text dates to date objects.
    yields: (name1, name2, date(birthdate))
    """
    with open(queryfile, 'rb') as f:
        reader = csv.reader(f)

        # Verify the header row is as expected as a sanity check
        hdr = reader.next()
        if hdr != ["name1", "name2", "birthdate"]:
            raise ValueError("The file '{}' is incorrectly formatted. Header row does not match expected header row.".format(queryfile))

        # Then, process each line as a query
        for [name1, name2, birthdate] in reader:
            yield name1, name2, dt(birthdate)

def query(registry, name1, name2, birthdate, output=True):
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
    for b in dateRange(birthdate):
        if match(name1, name2, b, registry):
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
    protEntries = [protectRecord(n1, n2, dt(bd)) for (n1,n2,bd) in textEntries]
    appendRegistry(protEntries)

def dt(txt, fmt='%Y-%m-%d'):
    """
    Parse a text in YYYY-mm-dd format and returns a datetime.date.
    """
    return datetime.strptime(txt, fmt).date()

def loadRegistry(registryfile=defaultRegistryFile):
    with open(registryfile, 'rt') as f:
        registry = set([x.strip() for x in f])
    return registry

######
# Tests
#

def _writeTestFile(tmpdir, fname, contents):
    """
    Creates a file for testing in the py.test temporary directory
    """
    tmpfile = tmpdir.join(fname)
    tmpfile.write("\n".join(contents))
    return str(tmpfile)

def test_processQueryFile(tmpdir):
    """
    Tests processing a query file
    """
    # Write a test registry file
    rfile = _writeTestFile(tmpdir, 'registry', _getTestRegistry())

    # Write a query CSV
    queryEntries = [
        # Exact match
        ("Malika", "Rhoades", date(1910, 05, 20)), 
        # Complete match name-swap
        ("Weeks","Leola",   date(1920, 05, 20)), 
        # No match
        ("Not","HERE",  date(1930, 05, 20)), 
        # Partial match, day/month swap
        ("Sant ina","Rayford'  ", date(1940, 10, 05)), 
        # No match
        ("No match", "here", date(1950, 05, 20)) 
    ]
    qfile =_writeTestQueryfile(tmpdir, 'query.csv', queryEntries)

    # Query and check the results
    assert(processQueryFile(qfile, rfile) == (2,1))

def _writeTestQueryfile(tmpdir, fname, entries):
    """
    Generates a temporary query file for testing
    """
    # Add a header row and converts dates to strings and combine into a CSV
    contents = ["name1,name2,birthdate"] + \
        [",".join([n1,n2,str(d)]) for (n1,n2,d) in entries]
    return _writeTestFile(tmpdir, fname, contents)

def test_readQueryfile(tmpdir):
    """
    Tests reading an error-free query file
    """
    # Write a query CSV
    entries = [
        ("Malika", "Rhoades", date(1910, 05, 20)), 
        ("Leola",  "Weeks",   date(1920, 05, 20)), 
        ("Yevette","Dortch",  date(1930, 05, 20)), 
        ("Santina","Rayford", date(1940, 05, 10)), 
        ("Benita", "Harwell", date(1950, 05, 20)), 
        ("Phylis", "Bravo",   date(1960, 05, 20)), 
        ("Joslyn", "Martell", date(1970, 05, 20)), 
        ("Callie", "Sweet",   date(1980, 05, 20)), 
        ("Sondra", "Harlan",  date(1990, 05, 20)), 
        ("Angla",  "Lockett", date(2000, 05, 20))  
    ]
    qfile = _writeTestQueryfile(tmpdir, 'query.csv', entries)

    # Read the file and make sure it matches
    readback = [x for x in enumerateCsv(qfile)]
    assert(entries == readback)

def _getTestRegistry():
    """
    Builds an in-memory registry for testing.
    """
    registryEntries = [
        ("Malika", "Rhoades", date(1910, 05, 20)), 
        ("Leola",  "Weeks",   date(1920, 05, 20)), 
        ("Yevette","Dortch",  date(1930, 05, 20)), 
        ("Santina","Rayford", date(1940, 05, 10)), 
        ("Benita", "Harwell", date(1950, 05, 20)), 
        ("Phylis", "Bravo",   date(1960, 05, 20)), 
        ("Joslyn", "Martell", date(1970, 05, 20)), 
        ("Callie", "Sweet",  date(1980, 05, 20)), 
        ("Sondra", "Harlan",  date(1990, 05, 20)), 
        ("Angla",  "Lockett", date(2000, 05, 20))  
    ]

    # Build an in-memory registry
    return set([protectRecord(n1,n2,b) for (n1,n2,b) in registryEntries])

def test_loadRegistry(tmpdir):
    # Dummy registry for testing
    r = [
        b64enc("1234567890"),
        b64enc("0987654321"),
        b64enc("asdfadfsadfs;dfs"),
        b64enc(";13lk4nrpoaindpoiuandfovpins"),
        b64enc("97810424327890301978134790")
    ]
    rfile = _writeTestFile(tmpdir, 'dummy-registry', r)
    assert(set(r) == loadRegistry(rfile))

def test_queryNoMatch():
    """
    Test no-match queries
    """
    r = _getTestRegistry()

    # No matches
    nomatch = (False, False)

    # Nothing close
    assert(query(r, "Ben", "Stein", date(2000, 01, 01)) == nomatch)

    # Wrong first name
    assert(query(r, "Fred", "Sweet", date(1980, 05, 20)) == nomatch)

    # Wrong bdate
    assert(query(r, "Callie", "Sweet", date(1980, 01, 20)) == nomatch)

def test_queryPartialMatch():
    """
    Test no-match queries
    """
    r = _getTestRegistry()

    # Partial match 
    pmatch = (False, True)

    # year within 10
    assert(query(r, "Joslyn", "Martell", date(1980, 05, 20)) == pmatch)

    # Day within 1
    assert(query(r, "Sondra", "Harlan",  date(1990, 05, 19)) == pmatch)

    # Name swap + day/month swap
    assert(query(r, "Rayford", "Santina", date(1940, 10, 05)) == pmatch)

def test_queryCompleteMatches():
    """
    Test complete matching for query()s
    """
    r = _getTestRegistry()

    # Complete match
    cmatch = (True, False)

    # Straight match
    assert(query(r, "Malika", "Rhoades", date(1910, 05, 20)) == cmatch)
    assert(query(r, "Phylis", "Bravo",   date(1960, 05, 20)) == cmatch)

    # Name swap
    assert(query(r, "Rhoades", "Malika", date(1910, 05, 20)) == cmatch)
    assert(query(r, "Bravo", "Phylis",  date(1960, 05, 20)) == cmatch)

    # Name swap and typo correct
    assert(query(r, "Rhoad'es", " MALIKA", date(1910, 05, 20)) == cmatch)
    assert(query(r, "BRA vo", "Phy lis ;",  date(1960, 05, 20)) == cmatch)

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
