"""
Routines for operating on CSV files containing demographic information.
"""
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA512
from base64 import urlsafe_b64encode as b64enc, urlsafe_b64decode as b64dec
from collections import namedtuple
from datetime import datetime, date
from shutil import copyfile
import binascii, csv, json, os

###
#
# Process settings

# Constants
defaultSettingsFile = 'settings/settings.json'
protectedRecordHeader = "recordId,exactMatch,siteId,hash"

def loadSettings(settingsfile=defaultSettingsFile):
    """
    Loads the current settings for this application.
    """
    try:
        settings = readSettingsFile(settingsfile)
    # Catch file IO errors
    except IOError as e:
        printSettingsError(settingsfile, e)
    # And JSON parsing errors
    except ValueError as e:
        printSettingsError(settingsfile, e)

    # Expand all paths
    for k,path in settings.iteritems():
        path = os.path.expanduser(os.path.expandvars(path))
        settings[k] = path
    return settings

def readSettingsFile(settingsfile):
    """
    Overwrite defaults dict with any values found in settingsfile
    """
    settings = {}
    with open(settingsfile, 'r') as f:
        settings = json.loads(f.read())
    for k,v in settings.items():
        settings[k] = str(v)

    return settings

def writeDefaultSettings(settingsfile=defaultSettingsFile):
    """
    Writes the defaults settings to a file.
    """
    with open(settingsfile, 'w') as f:
        f.write(json.dumps(defaultSettings))

def printSettingsError(settingsfile, e):
    print "Error: there was problem loading settings file '{}': "\
        "{}\n".format(settingsfile, e)
    exit(1)

###
#
# Log and segregate problematic input files
def noteError(srcfile, errMsg, cmd, settings, terminate):
    _, filename = os.path.split(srcfile)

    # Log the error
    with open(settings["errorLog"], 'a') as log:
        log.write("{}\tERROR\tError occurred while processing source file "\
            "'{}' with command '{}': {}\n".format(
                datetime.now(), 
                filename, 
                errMsg,
                cmd)
            )
    # Put a copy of the problematic file in the errorfile location
    copyfile(srcfile, os.path.join(settings["errorDir"], filename))
    print str(errMsg)
    if terminate:
        exit(1)

###
#
# Process JEE files against a registry.csv

def processJee(jeeFile, protectedRegistryFile, privkeyFile):
    # Read the protected registry contents into memory
    exact, partial = readProtectedRegistry(protectedRegistryFile)

    # Read the JEE into memory
    with open(jeeFile, 'rb') as f:
        jeeText = f.read()

    # Decrypt and verify the JEE contents
    err, reportingTxt = publicKeyDecrypt(privkeyFile, jeeText)
    if err is not None:
        return err

    recordCount, matchFound = match(reportingTxt, exact, partial)

    print "Processed {} uploaded records against {} registry entries".format(
        recordCount, len(exact))
    if matchFound == False:
        print "No matches found"

def readProtectedRegistry(protectedRegistryFile):
    """
    Reads records from a protected registry and divides into two dictionaries
    that map record->(recordId, siteId).
    @return: (exactMatchDict, partialMatchDict)
    """
    exactMatch, partialMatch = {}, {}

    # Iterate the protected registry file one line at a time
    def regReader():
        with open(protectedRegistryFile, 'r') as f:
            for line in f:
                yield line.strip()

    # Divide the registry records by exact and partial matches
    for record in parseProtectedRecords(regReader()):
        # Insert into the correct dictionary
        if record.isExact:
            table = exactMatch
        else:
            table = partialMatch
        table[record.hash] = record.siteId

    return exactMatch, partialMatch

def match(reportingTxt, exactMatchTable, partialMatchTable):
    """
    Matches reported protected entries against exact and partial 
    dictionaries from the registry.
    """
    # Keep a list of which record IDs have been matched so we don't 
    # perform duplicative matching.
    recordsMatched = set()
    recordCount = 0

    # Keep a list of all errors encountered
    errors = []

    # Iterator over individual lines in our reporting file
    def reportReader():
        for line in reportingTxt.split("\n"):
            yield line

    # Process the registry entries against the protected entries
    for record in parseProtectedRecords(reportReader()):
        recordCount += 1

        # Skip any records that have already been matched with this
        # record ID
        if record.recordId in recordsMatched:
            continue

        # Print a match and record the record ID
        def reportMatch(table, isExactMatch):
            # Grab the registry site ID from the table
            registrySiteId = table[record.hash]

            if isExactMatch:
                matchType = "exact"
            else:
                matchType = "partial"

            # Print a message
            printLines("Found {} match: {}".format(matchType, record.hash),
                "  Reporting site: {}".format(record.siteId),
                "  Registry site:  {}".format(registrySiteId),
                "")

            # Record the record ID
            recordsMatched.add(record.recordId)

        # First check for an exact match
        if record.hash in exactMatchTable:
            reportMatch(exactMatchTable, record.isExact)

        # Then a partial match
        elif record.hash in partialMatchTable:
            reportMatch(partialMatchTable, isExactMatch=False)

    anyMatchFound = len(recordsMatched) > 0
    return (recordCount, anyMatchFound)


###
#
# Operate on files containing demographic info in CSV format

def processRegistry(registryCsvfile, registryOutfile):
    """
    Processes a registry CSV and produces a new CSV file containing protected
    records.
    """
    # We apply _all_ of the alternate matching logic when producing
    # the registry
    iterator = protectAndFormat(
        registryCsvfile,
        reverseNames=True, 
        includeAltNames=True, 
        includeAltDates=True)

    # Write each protected record to the CSV file
    with open(registryOutfile, "w") as f:
        for entry in iterator:
            f.write(entry + "\n")

def processReports(inputfile, outfile, recipientKeyfile, debug=False):
    """
    Process (and validate) and file of demographic info and create an
    encrypted output file that contains protected records and is encrypted
    under the key retrieved from the file.
    """
    # For site reporting, we include alternate names (first initials)
    # so they can be partially matched at the registry.
    # The other alternates forms don't need to be produced, they'll
    # be matched automatically if an input error was made 
    # (day-month swap, etc)
    iterator = protectAndFormat(
        inputfile,
        reverseNames=False, 
        includeAltNames=True,
        includeAltDates=False)

    # Generate an entire CSV of protected records in memory so they
    # can be encrypted
    csvTxt = "\n".join([x for x in iterator])

    if debug:
        print csvTxt

    # Encrypt the contents and write the encrypted version to a file
    # in JEE format (JSON Encrypted Envelope)
    with open(outfile, "w") as f:
        f.write(publicKeyEncrypt(recipientKeyfile, csvTxt))

def parseProtectedRecords(recordIterator):
    """
    Reads raw strings from a record iterator and parses them as rows in a 
    protected record file. Any parse errors raise a FileParseError.
    @yields: ProtectedRecord
    """
    # Check the header on the first pass
    hdr = True

    lineNumber = -1
    for row in recordIterator:
        lineNumber += 1

        # Verify the header row is well-formed
        if hdr:
            if row != protectedRecordHeader:
                raise FileParseError("Header row does not match expected "\
                    "header")
            hdr = False
            continue

        # Parse each row and check for errors
        record = parseRow(row)
        if record.err is not None:
            raise FileParseError(fmtParseError(lineNumber, row, record.err))

        yield record

def fmtParseError(lineNumber, row, err):
    return "Could not parse line {}: {}\nError is: {}\n".format(
    lineNumber, row, record.row)

def parseRow(txt):
    """
    Process a row that contains protected demographic information.
    @returns: namedtuple.ProtectedRecord(err, 
        recordId, isExact, siteId, hash)
    """
    ProtectedRecord =  namedtuple("ProtectedRecord", 
        "err recordId isExact siteId hash")
    
    # Split and verify each row
    columns = txt.strip().split(",")
    if len(columns) != 4:
        err = "Expected 4 columns, but found {} columns".format(len(columns))
        return ProtectedRecord(err=err)

    # Pull out fields 
    recordIdTxt, isExactTxt, siteId, entry = columns

    # Parse recordId
    try:
        recordId = int(recordIdTxt)
    except ValueError:
        err = "Couldn't convert record ID '{}' to an integer value".format(
            recordIdTxt)
        return ProtectedRecord(err=err)

    # Parse isExact
    if isExactTxt.lower() == "true":
        isExact = True
    elif isExactTxt.lower() == "false":
        isExact = False
    else:
        err = "Unknown matching identifier in first column. Expected: "\
            "[True|False] but found {}.".format(isExact)
        return ProtectedRecord(err=err)

    # Looks good
    return ProtectedRecord(None, recordId, isExact, siteId, entry)

def protectAndFormat(inputfile, reverseNames, includeAltNames, 
    includeAltDates):
    """
    Reads and validates a CSV of demographic info and yields formatted
    records with demographic information processed with the hash
    function. 

    Caller provides True/False to indicate the following:

    reverseNames: return an exact match record with names in each order
        (name1,name2) and (name2,name2)

    includeAltNames: produce partial matching records with alternate names 
        (like first initials)

    includeAltDates: produce partial matching records with alternate
        birthdates (day-month swap, day +-, year+-)

    yields: a single record (line) for a CSV file
    """
    # Start with a header row
    yield protectedRecordHeader 

    # Process validates entries read from the input file
    recordId = -1
    for (s,n1,n2,bdate) in enumerateCsv(inputfile):
        recordId += 1
        n1,n2 = normalize([n1,n2])

        # Yield the exact match records
        yield fmtOutput(recordId, s, n1, n2, bdate, exactMatch=True)

        if reverseNames:
            yield fmtOutput(recordId, s, n2, n1, bdate, exactMatch=True)

        # Run through partial match permutations
        if includeAltNames:
            for altn1,altn2 in alternateNames(n1,n2):
                yield fmtOutput(recordId, s, altn1, altn2, bdate, 
                    exactMatch=False)

        if includeAltDates:
            for altBdate in alternateDates(bdate):
                yield fmtOutput(recordId, s, n1, n2, altBdate, 
                    exactMatch=False)

def fmtOutput(recordId, siteId, name1, name2, bdate, exactMatch):
    """
    Formats a protected CSV entry:
    @returns "recordId,isExactMatch,siteId,b64ProtectedEntry"
    """
    return '{},{},{},{}'.format(str(recordId),str(exactMatch), siteId, 
        protectEntry(name1, name2, bdate))

def enumerateCsv(inputfile):
    """
    Reads and validates a CSV file of demographic information. 
    Requires a well-formed header row and converts text dates to date objects.
    yields: (siteId, name1, name2, date(birthdate))
    """
    with open(inputfile, 'rt') as f:
        reader = csv.reader(f)

        # Verify the header row is as expected as a sanity check
        hdr = reader.next()
        if hdr != ["siteId", "name1", "name2", "birthdate"]:
            raise error(ValueError, """The file '{}' is incorrectly formatted. 
                Header row does not match expected header row.""",
                inputfile)

        # Then, process each line as a query
        for [siteId, name1, name2, birthdate] in reader:
            yield str(siteId), name1, name2, dt(birthdate)

def alternateNames(n1,n2):
    """
    Produces alternate names for partial matching:
    name1-initial + name2
    name2-initial + name1
    """
    yield n1[:4] + n2, None
    yield n2[:4] + n1, None

def alternateDates(orig, dayOffsets=[1,-1], yearOffsets=None, 
    swapMonthDay=True):
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
    if dayOffsets:
        for day in offsetRange(orig.day, dayOffsets):
            d = replace(orig, day=day) 
            if d is not None:
                yield d

    # Iterate through all year offsets and return all valid dates
    if yearOffsets:
        for year in offsetRange(orig.year, yearOffsets):
            d = replace(orig, year=year) 
            if d is not None:
                yield d

def offsetRange(value, offsets):
    """
    Enumerates a range of discrete offsets excluding the value.
    """
    for offset in offsets:
        yield value + offset

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

def protectEntry(name1, name2, birthdate, debug=False):
    """
    Protects a single record of demographic info by applying SHA512.
    """    
    assert(type(birthdate) is date)
    name = "".join([x for x in [name1,name2] if x is not None])
    sha = SHA512.new(data=name)
    sha.update(birthdate.isoformat())

    if debug:
        print name + birthdate.isoformat()

    return b64enc(sha.digest() )

def normalize(names):
    """
    Remove non-ASCII, non-alphanumeric characters, scrub known prefixes and 
    suffixes, returns all names in uppercase.
    """
    # Strips non-alphabetical characters, converts to uppercase, 
    # removes known suffixes and prefixes.
    def stripAndUp(txt):
        txt = scrubPrefixes(txt)
        txt = scrubSuffixes(txt)
        return ("".join(ch for ch in txt if ch.isalpha())).upper()

    # Normalize each name and return as a list
    # Discard any None values
    return [stripAndUp(n) for n in names if n is not None]

def scrubPrefixes(name):
    """
    Removes commonly seen prefixes.
    """
    prefixes = ["Mr.", "Ms.", "Mrs.", "Dr.", "Mr", "Ms", "Mrs", "Dr", "Miss"]
    names = name.split()
    if names[0] in prefixes:
        names = names[1:]
    else:
         names = names[0:]
    return ' '.join(names)

def scrubSuffixes(name):
    """
    Removes commonly seen suffixes.
    """
    suffixes = ["I", "II", "III", "IV", "Jr.", "Sr.", "Jr", "Sr", "MA", "MD", "1st", "2nd", "3rd"]
    names = name.split()
    if names[-1] in suffixes:
        names = names[:-1]
    else:
         names = names[0:]
    return ' '.join(names)

class FileParseError(Exception):
    """
    Indicates that an input file failed parsing or verification and should
    be discarded.
    """
    def __init__(self, msg):
        Exception.__init__(self, msg)

###
# 
# Work with encrypted files

# Constants
symmetricKeySizeBytes = 128/8
encMsgKeyBytes = 384
rsaKeySize = 3072

publicKeyDecryptError = "This is an rsa PUBLIC key, but an rsa PRIVATE key "\
    "is required for decryption."
decryptionFailedError = "Decryption failed. Encrypted message is not valid."

def publicKeyEncrypt(recipientKeyfile, message):
    """
    Applies public key (hybrid) encryption to a given message when supplied 
    with a path to a public key (RSA in PEM format).
    """
    # Load the recipients pubkey from a PEM file
    with open(recipientKeyfile, 'rb') as f:
        recipientKey = RSA.import_key(f.read())

    # Encrypt the message with AES-GCM using a newly selected key
    messageKey, ctext = aesEncrypt(message)

    # Encrypt the message key and prepend it to the ciphertext
    cipher = PKCS1_OAEP.new(recipientKey)
    encMsg = cipher.encrypt(messageKey) + ctext

    # Format the message into JSON
    return createJee(recipientKey, encMsg)

def publicKeyDecrypt(privkeyFile, jee):
    """
    Decrypts an encrypted message with a private (RSA) key.
    Returns: (err, message)
    """
    privkey = None
    with open(privkeyFile, 'rb') as f:
        privkey = RSA.import_key(f.read())

    # Verify that this is a private key
    if not privkey.has_private():
        return (publicKeyDecryptError, None)

    # Verify the JEE and extract the encrypted message
    err, encMsg = decodeAndVerifyJee(privkey.publickey(), jee)
    if err:
        return (err, None)

    # Separate the encrypted message key from the symmetric-encrypted portion.
    encKey, ctext = encMsg[:encMsgKeyBytes], encMsg[encMsgKeyBytes:]

    # Recover the message key
    msgKey = PKCS1_OAEP.new(privkey).decrypt(encKey)

    # Recover the underlying message
    try:
        return (None, aesDescrypt(msgKey, ctext))
    except ValueError:
        return (decryptionFailedError, None)

def createJee(pubkey, encMsg):
    """
    Packages a ciphertext into a JSON encryption envelope. Example:
    { 
        "typ": "jee",
        "alg": "RSA-PKCS1-OAEP-AES128-GCM",
        "pk_fp_alg": "PEM-SHA256",
        "pk_fp": "base64=",
        "enc_data": "base64="
    }
    """
    env = {
        "typ": "jee", 
        "alg": "RSA-PKCS1-OAEP-AES128-GCM",
        "pk_fp_alg": "PEM-SHA256",
        "pk_fp": b64enc(pkFingerprint(pubkey)),
        "enc_msg": b64enc(encMsg)
    }
    return json.dumps(env)

def decodeAndVerifyJee(pubkey, jeeText):
    """
    Parses and verifies a JSON encryption envelope against our default settings.
    Verifies the pubkey fingerprint against the pubkey provided.    
    Returns: (err, enc_data)
    """
    env = {}
    try:
        env = json.loads(jeeText)
    except ValueError as err:
        return (str(err), None)

    expectedFpB64 = b64enc(pkFingerprint(pubkey))

    # Probes the env dictionary for an expected k,v pair
    def check(k, v):
        return k in env and env[k] == v

    # Check for expected fields and values
    if not check("typ", "jee"):
        return (None, "Unknown packaging type -- expected typ=jee")

    if not check("alg", "RSA-PKCS1-OAEP-AES128-GCM"):
        return (None, "Unknown encryption algorithm -- expected alg='RSA-PKCS1-OAEP-AES128-GCM'")

    if not check("pk_fp_alg", "PEM-SHA256"):
        return (None, "Unknown public key fingerprint algorithm -- expected pk_fp_alg='PEM-SHA256'")

    if not check("pk_fp", expectedFpB64):
        return (None, "Public key fingerprint mismatch.")

    if not "enc_msg" in env or len(env["enc_msg"]) == 0:
        return (None, "Encrypted message is missing or empty (enc_msg)")

    return None, b64dec(str(env["enc_msg"]))

def pkFingerprint(pubkey):
    """
    Generates pubkey fingerprint using our fingerprinting technique:
    SHA256(pem-encoded-pubkey)
    """
    return SHA256.new(data=pubkey.exportKey(format='PEM')).digest()

def createPubkeyPair(basename):
    """
    Creates a new secret/key pubkey pair and writes them to distinct files:
    <basename>-public.pem
    <basename>-private.pem
    """
    pubFilename = basename + "-public.pem"
    privFilename = basename + "-private.pem"

    # Create a new key and write both key versions to the correct file
    privkey = RSA.generate(rsaKeySize)
    pubkey = privkey.publickey()
    _writePemFile(pubFilename, pubkey)
    _writePemFile(privFilename, privkey)

def _writePemFile(filename, key):
    with open(filename, "w") as outfile:
        outfile.write(key.exportKey(format='PEM'))

def aesEncrypt(message):
    """
    Encrypts a message with a fresh key using AES-GCM. 
    Returns: (key, ciphertext)
    """
    key = get_random_bytes(symmetricKeySizeBytes)
    cipher = AES.new(key, AES.MODE_GCM)
    ctext, tag = cipher.encrypt_and_digest(message)

    # Concatenate (nonce, tag, ctext) and return with key
    return key, (cipher.nonce + tag + ctext)

def aesDescrypt(key, ctext):
    """
    Decrypts and authenticates a ciphertext encrypted with with given key.
    """
    # Break the ctext into components, then decrypt
    nonce,tag,ct = (ctext[:16], ctext[16:32], ctext[32:])
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.decrypt_and_verify(ct, tag)

###
## Utilities

def printLines(*args):
  print "\n".join(list(args))

def dt(txt, fmt='%Y-%m-%d'):
    """
    Parse a text in YYYY-mm-dd format and returns a datetime.date.
    """
    return datetime.strptime(txt, fmt).date()

def error(errorType, msg, *args, **kwargs):
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
