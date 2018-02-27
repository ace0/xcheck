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

def test_normalize():
    """
    Simple known-answer tests
    """
    assert(normalize(["Avery","Bales"]) == ["AVERY", "BALES"])
    assert(normalize(["Idell", "Leggett"]) == ["IDELL", "LEGGETT"])
    assert(normalize(["Farah", "Sharkey"]) == ["FARAH", "SHARKEY"])
    assert(normalize(["Alla", "Creamer"]) == ["ALLA", "CREAMER"])

def test_normalizeWithNone():
    """
    Tests normalize is one param is None
    """
    assert(normalize([None,"Bales"]) == ["BALES"])
    assert(normalize(["Idell", None]) == ["IDELL"])

def test_normalizeNonAlpha():
    """
    Tests that normalize handles non-alphanumeric characters
    """
    assert(normalize(["Ave3ry","Bales1"]) == ["AVERY","BALES"])
    assert(normalize(["Idell", "Legg`ett"]) == ["IDELL","LEGGETT"])
    assert(normalize(["2Farah", "Sharkey"]) == ["FARAH","SHARKEY"])
    assert(normalize(["Alla", "Creamer4"]) == ["ALLA","CREAMER"])
    assert(normalize(["Lavinia\xe2", "Barnhart"]) == ["LAVINIA","BARNHART"])

def test_normalizeSpaces():
    """
    Tests that normalize removes whitespace: spaces, tabs, newlines
    """
    assert(normalize(["Florance", "  Arevalo"]) == ["FLORANCE","AREVALO"])
    assert(normalize(["Trinidad   ", "Langley\n"]) == ["TRINIDAD","LANGLEY"])
    assert(normalize(["Ro mona", "Da ly"]) == ["ROMONA","DALY"])
    assert(normalize(["  El freda ", "    Micha ud     "]) == ["ELFREDA","MICHAUD"])
    assert(normalize(["  Tamela", "Garris"]) == ["TAMELA","GARRIS"])

def test_normalizePrefixSuffix():
    """
    Tests that normalize always matches reversed names
    """
    assert(normalize(["Dr  Avery","Bales"]) == ["AVERY","BALES"])
    assert(normalize([" Idell", " Leggett III "]) == ["IDELL","LEGGETT"])
    assert(normalize(["Farah", "Sharkey Jr "]) == ["FARAH","SHARKEY"])
    assert(normalize(["Mrs Alla", "Creamer"]) == ["ALLA","CREAMER"])
    assert(normalize(["Ms. Lavinia ", "Barnhart"]) == ["LAVINIA","BARNHART"])

def test_alternateDates():
    d = date(2000, 5, 20)
    expected = set([
        # year +-10
        date(1990, 5, 20), 
        date(2010, 5, 20), 

        # day +-1
        date(2000, 5, 19),
        date(2000, 5, 21)
    ])
    actual = alternateDates(d, 
        dayOffsets=[1,-1], 
        yearOffsets=[10,-10],
        swapMonthDay=True)
    assert(set(actual) == expected)

def test_alternateDatesSwap():
    founded = date(1848, 6, 5)
    actual = [x for x in alternateDates(founded, yearOffsets=None, dayOffsets=None)]
    assert(actual == [date(1848, 5, 6)])

def test_alternateDatesOutOfRange():
    """
    Ensures that alternateDates exclude dates that are out of range.
    """
    founded = date(1817, 01, 29)
    expected = [date(1817, 01, 24)]
    actual = [x for x in alternateDates(founded, yearOffsets=None, 
        dayOffsets=[-5,+5], swapMonthDay=False)]
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

def test_pkDecryptWithPubkey():
    message = "Three may keep a secret, if two of them are dead."
    jee = publicKeyEncrypt("samples/testkey-public.pem", message)
    err, recoveredMessage = publicKeyDecrypt("samples/testkey-public.pem", jee)
    print "err: ", err
    print "recoveredMessage: ", recoveredMessage
    assert(recoveredMessage is None)
    assert(err == publicKeyDecryptError)

def test_pkEncryptRoundTrip():
    message = "Three may keep a secret, if two of them are dead."
    jee = publicKeyEncrypt("samples/testkey-public.pem", message)
    err, recoveredMessage = publicKeyDecrypt("samples/testkey-private.pem", jee)
    assert(err is None)
    assert(message == recoveredMessage)

# This test is slow -- disabling 
def _test_createKeyPair():
    createPubkeyPair("./testkey")

def test_aesEncryptRoundTrip(): 
    message = "This is a long message that we want to verify can be decrypted exactly"
    key, ctext = aesEncrypt(message)
    recoveredMessage = aesDescrypt(key, ctext)
    assert(message == recoveredMessage)

def test_aesDetectsCtextError():
    message = "This message is expected to fail verification"
    key, ctext = aesEncrypt(message)
    ctext = ctext[:20] + b'\x55' + ctext[21:]
    with pytest.raises(ValueError, message="MAC check failed"):
        recoveredMessage = aesDescrypt(key, ctext)