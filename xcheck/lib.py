"""
Routines for operating on CSV files containing demographic information.
"""
from Crypto.Hash import SHA512

from base64 import urlsafe_b64encode as b64enc, urlsafe_b64decode as b64dec
# from base64 import
from datetime import datetime, date
import csv

def processCheckins(inputfile):
    """
    Reads and validates a CSV of demographic info and produces protected
    records for various permuations on the birthdate.
    each entry according to the dateRange() function.
    yields (isExactInfo, b64ProtectedRecord) 
    """
    # Process validates entries read from the input file
    for (n1,n2,bdate) in enumerateCsv(inputfile):
        # Yield the complete match record
        yield fmtOutput(True, (n1,n2,bdate))

        # Yield each alternative birthdate
        for altBdate in dateRange(bdate):
            yield fmtOutput(False, (n1,n2,altBdate))

def fmtOutput(exactMatch, record):
    """
    Formates a protected CSV entry as:
    exactMatch, protect(record)
    @record=(name1,name2,birthdate)
    """
    return '{},{}'.format(str(exactMatch), protectRecord(*record))

def enumerateCsv(inputfile):
    """
    Reads and validates a CSV file of demographic information. 
    Requires a well-formed header row and converts text dates to date objects.
    yields: (name1, name2, date(birthdate))
    """
    with open(inputfile, 'rt') as f:
        reader = csv.reader(f)

        # Verify the header row is as expected as a sanity check
        hdr = reader.next()
        if hdr != ["name1", "name2", "birthdate"]:
            raise err(ValueError, """The file '{}' is incorrectly formatted. 
                Header row does not match expected header row.""",
                inputfile)

        # Then, process each line as a query
        for [name1, name2, birthdate] in reader:
            yield name1, name2, dt(birthdate)

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

def protectRecord(name1, name2, birthdate):
    """
    Protects a single record of demographic info by applying SHA512.
    """
    name = canonize(name1, name2)
    assert(type(birthdate) is date)
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

def dt(txt, fmt='%Y-%m-%d'):
    """
    Parse a text in YYYY-mm-dd format and returns a datetime.date.
    """
    return datetime.strptime(txt, fmt).date()

def err(errorType, msg, *args, **kwargs):
    """
    Quickly build an error or exception with a formatted message.
    """
    fmtMsg = slim(msg.format(*args, **kwargs))
    return errorType(fmtMsg)

def slim(txt):
    """
    Replaces any instances of multiple spaces with a single space
    """
    return ' '.join(txt.split())
