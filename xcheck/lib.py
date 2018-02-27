"""
Routines for operating on CSV files containing demographic information.
"""
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA512
from base64 import urlsafe_b64encode as b64enc, urlsafe_b64decode as b64dec
from datetime import datetime, date
from shutil import copyfile
import binascii, csv, json, os

###
#
# Process settings

# Constants
defaultSettingsFile = 'settings/settings.json'
defaultSettings = {
    # Registry operators on Windows: create a folder to store the registry
    # private key and update the registryPrivkeyfile entry.
    #
    # Example:
    # "registryPrivkeyfile": "C:\\Users\\User\\privkeys", 

    # Unix users can use the .ssh directory to store private keys
    "registryPrivkeyfile": "~/.ssh/registry-private.pem", 
    "registryPubkeyfile": "settings/registry-public.pem", 
    "protectedFile": "./protected.jee",
    "registryFile": "settings/protected-registry.csv",
    "errorDir": "errors",
    "errorLog": "settings/errorLog"
    }

def loadSettings(settingsfile=defaultSettingsFile):
    """
    Loads the current settings for this application.
    """
    settingsFromFile = {}
    try:
        settingsFromFile = readSettingsFile(settingsfile)
    # Catch file IO errors
    except IOError as e:
        printSettingsError(settingsfile, e)
    # And JSON parsing errors
    except ValueError as e:
        printSettingsError(settingsfile, e)

    # Start with the default settings and overwrite any settings
    # read from the file.
    settings = defaultSettings.copy()
    settings.update(settingsFromFile)

    # Expand all paths
    for k,path in defaultSettings.iteritems():
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
    print "Warning: there was problem loading settings file '{}': {}\n"\
        "Using default settings instead.".format(settingsfile, e)

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

def match(reportingTxt, exactMatchTable, partialMatchTable):
    """
    Matches reported protected entries against exact and partial 
    dictionaries from the registry.
    """
    def printMatch(matchType, entry, reportingSite, registrySite):
        printLines("Found {} match: {}".format(matchType, entry),
            "  Reporting site: {}".format(reportingSite),
            "  Registry site:  {}".format(registrySite),
            "")

    # Process the registry entries against the protected entries
    recordCount = 0
    anyMatchFound = False
    for group in groupReportedRecords(parseReportedRecords(reportingTxt)):
        recordCount += len(group)
        for reportingSite,entry in group:
            # Check for a match in one of the registry dictionaries
            def checkMatch(registry, matchType):
                if entry not in registry:
                    return False
                printMatch(matchType, entry, 
                    reportingSite=reportingSite, 
                    registrySite=registry[entry])
                anyMatchFound = True
                return True

            # First check for an exact match
            if checkMatch(exactMatchTable, "exact"):
                # Any match means stop process this group of entries
                break

            # Then a partial match
            if checkMatch(partialMatchTable, "partial"):
                # Any match means stop process this group of entries
                break

    return (recordCount, anyMatchFound)

def groupReportedRecords(recordIterator):
    """
    Groups protectedEntry into lists so that the first item is always an
    exact match entry followed by any partial match entries.
    yields: [(siteId,protectedEntry), (siteId,protectedEntry),...] 
    """
    group = []
    for isExact,siteId,entry in recordIterator:
        # Exact match marks the start of a new group. Yield any previous group
        # and reset
        if isExact:
            yield group
            group = []
        group.append((siteId,entry))
    # Yield the final group
    yield group

def parseReportedRecords(reportingTxt):
    """
    Parses reported text into rows and fields. Prints any parsing errors
    and discard these records.
    yields: isExactMatch,siteId,protectedEntry
    """
    rowCount = 0
    for row in reportingTxt.split("\n"):
        rowCount += 1
        err,isExact,reportingSiteId,protectedEntry = parseRow(row)

        # Report errors
        if err is not None:
            printLines("Found a problem in line number {}: {}".format(
                rowCount, err), 
                "  Original record is: {}".format(row),
                "  Skipping this record", 
                "")
            continue
        yield isExact,reportingSiteId,protectedEntry

def readProtectedRegistry(protectedRegistryFile):
    """
    Reads records from a protected registry and divides into two dictionaries
    that map record->siteId.
    @return: (exactMatchDict, partialMatchDict)
    """
    exactMatch, partialMatch = {}, {}

    with open(protectedRegistryFile, "r") as f:
        # Verify the header row is as expected as a sanity check
        hdr = f.readline().strip()
        if hdr != "exactMatch,siteId,protectedEntry":
            raise err(ValueError, """The file '{}' is incorrectly formatted. 
                Header row does not match expected header row.""",
                protectedRegistryFile)

        rowCnt = 1
        for row in f:
            rowCnt += 1
            err, isExact, siteId, protectedEntry = parseRow(row)

            if err is not None:
                printLines("Could not parse row {} -- skipping record.".format(rowCnt), 
                 " Problem was: " + err) 
                continue

            # Insert into the correct dictionary
            if isExact:
                exactMatch[protectedEntry] = siteId
            else:
                partialMatch[protectedEntry] = siteId        

    return exactMatch, partialMatch

def parseRow(txt):
    """
    Process a row that contains protected demographic information.
    @returns: (err, isExact, siteId, protectedEntry)
    """
    # Split and verify each row
    columns = txt.strip().split(",")
    if len(columns) != 3:
        err = "Expected 3 columns, but found {}".format(len(columns))
        return err, None, None, None

    # Pull out fields 
    isExactTxt, siteId, entry = columns

    # Parse isExact
    if isExactTxt.lower() == "true":
        isExact = True
    elif isExactTxt.lower() == "false":
        isExact = False
    else:
        err = "Unknown matching identifier in first column. " + \
            "Expected: [True|False] but found {}.".format(isExact)
        return err, None, None, None

    # Look good
    return None, isExact, siteId, entry

###
#
# Operate on files containing demographic info in CSV format

def processRegistry(registryCsvfile, registryOutfile):
    """
    Processes a registry CSV and produces a new file containing protected
    records.
    """
    with open(registryOutfile, "w") as f:
        f.write("exactMatch,siteId,protectedEntry\n")

        for entry in protectAndFormat(registryCsvfile, partialMatchDates=True, 
            partialMatchNames=True):
            f.write(entry)
            f.write("\n")

def processReports(inputfile, outfile, recipientKeyfile, debug=False):
    """
    Process (and validate) and file of demographic info and create an
    encrypted output file that contains protected records and is encrypted
    under the key retrieved from the file.
    """
    # Generate an entire protected record CSV in-memory
    txt = "\n".join([x for x in protectAndFormat(inputfile, 
        partialMatchDates=False, partialMatchNames=True)])

    if debug:
        print txt

    # Encrypt the contents and write it to a file
    with open(outfile, "w") as f:
        f.write(publicKeyEncrypt(recipientKeyfile, txt))

def protectAndFormat(inputfile, partialMatchDates, partialMatchNames):
    """
    Reads and validates a CSV of demographic info and yields formatted
    records with demographic information processed with the protectedEntry
    function.

    if partialMatch=True, partial match permutations are applied to each record.

    yields: (isExactInfo, siteId, b64ProtectedEntry) 
    """
    # Process validates entries read from the input file
    for (s,n1,n2,bdate) in enumerateCsv(inputfile):
        n1,n2 = normalize([n1,n2])

        # Yield the exact match record with names in either
        # direction.
        yield fmtOutput(s, n1, n2, bdate, exactMatch=True)
        yield fmtOutput(s, n2, n1, bdate, exactMatch=True)

        # Run through partial match permutations
        if partialMatchNames:
            for altn1,altn2 in alternateNames(n1,n2):
                yield fmtOutput(s, altn1, altn2, bdate, exactMatch=False)

        if partialMatchDates:
            for altBdate in alternateDates(bdate):
                yield fmtOutput(s, n1, n2, altBdate, exactMatch=False)

def fmtOutput(siteId, name1, name2, bdate, exactMatch):
    """
    Formats a protected CSV entry:
    @returns "isExactMatch,siteId,b64ProtectedEntry"
    """
    return '{},{},{}'.format(str(exactMatch), siteId, 
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
            raise err(ValueError, """The file '{}' is incorrectly formatted. 
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
