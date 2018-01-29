"""
Routines for operating on CSV files containing demographic information.
"""
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, SHA512
from base64 import urlsafe_b64encode as b64enc, urlsafe_b64decode as b64dec
from datetime import datetime, date
import binascii, csv, json

###
#
# Process settings

# Constants
defaultSettingsFile = 'settings/settings.json'
defaultSettings = {
    "protectedFile": "./protected.jee",
    "registryPubkeyfile": "settings/registry-public.pem",
    "registryPrivkeyfile": "~/.ssh/registry-private.pem",
    "registryFile": "settings/protected-registry"
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
    return settings

def readSettingsFile(settingsfile):
    """
    Overwrite defaults dict with any values found in settingsfile
    """
    settings = {}
    with open(settingsfile, 'r') as f:
        settings = json.loads(f.read())
    return settings

def writeDefaultSettings(settingsfile=defaultSettingsFile):
    """
    Writes the defaults settings to a file.
    """
    with open(settingsfile, 'w') as f:
        f.write(json.dumps(defaultSettings))

def printSettingsError(settingsfile, e):
    print "Warning: there was problem loading settings file '{}': {}\nUsing default settings instead.".format(
        settingsfile, e)

###
#
# Process JEE files against a registry.csv

def processJee(jeeFile, registryFile, privkeyFile):
    # Read the JEE into memory
    with open(jeeFile, 'rb') as f:
        jeeText = f.read()

    # Decrypt and verify the JEE contents
    err, protectedEntries = publicKeyDecrypt(privkeyFile, jeeText)
    if err is not None:
        return err

    # Segregate the protected entries into exact and partial matches
    exact, partial = segregate(protectedEntries)
    registryCount, matchFound = match(exact, partial, registryFile)

    print "Processed {} checkin entries against {} registry entries".format(len(exact), registryCount)
    if matchFound == False:
        print "No matches found"

def match(checkinExact, checkinPartial, registryFile):
    """
    Matches registry entries against exact and partial entries from a protected check-in file.
    """
    def printMatch(matchType, entry, reportingSite, registrySite):
        printLines("Found {} match: {}".format(matchType, entry),
            "  Reporting site: {}".format(reportingSite),
            "  Registry site:  {}".format(registrySite),
            "")

    # Process the registry entries against the protected entries
    matchFound = False
    registryCount = 0

    with open(registryFile, 'r') as f:
        for entry in f:
            (registrySite, precord) = entry.strip().split(",")
            registryCount += 1

            # TODO: Note that siteIds will need to switch once reporting/registry
            #       enumeration changes

            # First check for an exact match
            if precord in checkinExact:
                printMatch("exact", precord, checkinExact[precord], registrySite)
                matchFound = True

            # Then a partial match
            elif precord in checkinPartial:
                printMatch("partial", precord, checkinPartial[precord], registrySite)
                matchFound = True
    return (registryCount, matchFound)

def segregate(entries):
    """1
    Segregates a list of entries into two dictionaries that map record->siteId.
    @return: (exactMatchDict, partialMatchDict)
    """
    exactDict, partialDict = {}, {}
    cnt = 0
    for row in entries.split('\n'):
        cnt += 1
        isExact, siteId, entry = row.split(',')
        isExact = isExact.strip().lower()

        if isExact == "true":
            exactDict[entry] = siteId
        elif isExact == "false":
            partialDict[entry] = siteId
        else:
            print "Warning: Unknown matching identifier in first column of row {}. Expected: [True|False] but found {}.".format(
                cnt, isExact)

    return exactDict, partialDict

###
#
# Operate on files containing demographic info in CSV format

def processRegistry(registryCsvfile, registryOutfile):
    """
    Processes a registry CSV and produces a new file containing protected
    records.
    """
    with open(registryOutfile, 'wt') as f:
        for (s,n1,n2,d) in enumerateCsv(registryCsvfile):
            f.write(fmtOutput(s,n1,n2,d))
            f.write("\n")

def processCheckins(inputfile, outfile, recipientKeyfile):
    """
    Process (and validate) and fiel of demographic info and create an
    ecnrypted output file that contains protected records and is encrypted
    under the key retrieved from the file.
    """
    # Generate an entire proected record CSV in-memory
    txt = '\n'.join([x for x in permuteAndProtectCheckins(inputfile)])

    # Encrypt the contents and write it to a file
    with open(outfile, 'wt') as f:
        f.write(publicKeyEncrypt(recipientKeyfile, txt))

def permuteAndProtectCheckins(inputfile):
    """
    Reads and validates a CSV of demographic info and produces protected
    records for various permuations on the birthdate.
    each entry according to the dateRange() function.
    yields (isExactInfo, b64ProtectedRecord) 
    """
    # Process validates entries read from the input file
    for (s, n1,n2,bdate) in enumerateCsv(inputfile):
        # Yield the complete match record
        yield fmtOutput(s, n1, n2, bdate, exactMatch=True)

        # Yield each alternative birthdate
        for altBdate in dateRange(bdate):
            yield fmtOutput(s, n1, n2, altBdate, exactMatch=False)

def fmtOutput(siteId, name1, name2, bdate, exactMatch=None):
    """
    Formats a protected CSV entry. 
    If exactMatch is specified as a bool, returns:
    "isExactMatch,siteId,protect(record)"

    If exactMatch=None, returns:
    "siteId,protect(record)"
    @record=(siteId,name1,name2,birthdate)
    """
    record = protectRecord(name1, name2, bdate)
    if exactMatch is None:
        return '{},{}'.format(siteId, record)
    else:
        return '{},{},{}'.format(str(exactMatch), siteId, record)

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

def dateRange(orig, dayOffsets=[1,-1], yearOffsets=[10,-10], swapMonthDay=True):
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
    # Strips non-alphabetical characters, converts to uppercase, 
    # removes known suffixes and prefixes.
    def stripAndUp(txt):
        rv = scrubPrefixes(txt)
        rv = scrubSuffixes(rv)
        return ("".join(ch for ch in rv if ch.isalpha())).upper()

    # Strip and uppercase each name, sort to alphabetical order,
    # join and return
    return "".join(sorted([stripAndUp(n) for n in [name1,name2]]))

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
# Working with encrypted files

# Constants
symmetricKeySizeBytes = 128/8
encMsgKeyBytes = 384
rsaKeySize = 3072

publicKeyDecryptError = "This is an rsa PUBLIC key, but an rsa PRIVATE key is required for decryption."
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
        "pk_fp_alg": "SHA256",
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
    with open(filename, 'wt') as outfile:
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
