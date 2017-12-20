"""
Routines for operating on CSV files containing demographic information.
"""
from datetime import datetime, date
import csv

def permuteCsv(inputfile):
    """
    Reads, validates, and iterates a CSV of demographic info and permutes
    each entry according to the dateRange() function.
    yields (name2, name2, date(birthdate)
    """
    # Process validates entries read from the input file
    for (n1,n2,bdate) in enumerateCsv(inputfile):
        # Yield the complete match record
        yield (n1,n2,bdate)

        # Yield each alternative birthdate
        for altBdate in dateRange(bdate):
            yield (n1,n2,altBdate)

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

# def query(registry, name1, name2, birthdate, output=True):
#     """
#     Performs complete and partial matching of a given entry against a 
#     registry. 
#     Returns: (isCompleteMatch, isPartialMatch)
#     """
#     # First, check for a complete match
#     if match(name1, name2, birthdate, registry):
#         if output:
#             print "Complete match for entry: {} {} {}".format(name1, name2, birthdate)
#         return (True, False)

#     # Next check for partial matches
#     for b in dateRange(birthdate):
#         if match(name1, name2, b, registry):
#             if output:
#                 print "Partial match for entry: {} {} with reported birthday {} but matched to birthdate {}".format(name1, name2, birthdate, b)
#             return (False, True)

#     # No matching records found
#     return (False, False)    

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

def dt(txt, fmt='%Y-%m-%d'):
    """
    Parse a text in YYYY-mm-dd format and returns a datetime.date.
    """
    return datetime.strptime(txt, fmt).date()

# def loadRegistry(registryfile):
#     with open(registryfile, 'rt') as f:
#         registry = set([x.strip() for x in f])
#     return registry
