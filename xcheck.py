"""
Process protected infectious disease reports and patient queries.
"""
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from base64 import urlsafe_b64encode as b64encode
from base64 import urlsafe_b64decode as b64decode
import json, pytest

symmetricKeySizeBytes = 128/8
rsaKeySize = 3072
encMsgKeyBytes = 384

publicKeyDecryptError = "This is an rsa PUBLIC key, but an rsa PRIVATE key is required for decryption."
decryptionFailedError = "Decryption failed. Encrypted message is not valid."

# TODO
# - Refactor crypto code to crypto.py
# - Add command-line tools:
#   xcheck new-registry-key <basename>
#   xcheck process <query.csv> <registry.csv>
#   xcheck upload <query.csv>
#   xcheck registry-update <additions.csv> <registry.csv>
# - SFTP transfer
# - Make a registry update
# - Unpack, parse CSV, complete match
# - Partial match

def checkRegistry(name, date, registryfile="./registry"):
	registry = loadRegistry(registryfile)

def loadRegistry(registryfile="./registry"):
	registry = set()
	with open(registryfile) as f:
		[registry.add(entry) for entry in f]
	return registry

def hardenRecord(name, date, secret, iterations=1000):
	"""
	Registry records are hardened with an iterated hash combined with a secret.
	hr = b64( SHA256^{1000}(secret, name, date) )
	"""
	sha = SHA256.new(data=secret)
	sha.update(name)
	sha.update(stdDate(date))
	d = sha.digest()
	for _ in xrange(iterations):
		d = SHA256.new(data=d).digest()
	return b64encode(d)

def stdDate(date):
	"""
	Standardizes a date to ISO-8601: YYYY-MM-DD
	25-Dec-2000 => "2000-12-25"
	"""
	return date.isoformat()

def loadPrfSecret(secretfile="./.prfsecret"):
	"""
	Loads a PRF secret from the specified file. If the secretfile isn't
	present, it is created and populated with a fresh random value.
	"""
	s = open(secretfile, 'rb').read()
	if len(s) != symmetricKeySizeBytes:
		s = get_random_bytes(symmetricKeySizeBytes)
		with open(secretfile, 'wb') as f:
			f.write(contents)
	return s

def publicKeyEncrypt(recipientKeyfile, message):
	"""
	Applies public key (hybrid) encryption to a given message when supplied 
	with a path to a public key (RSA in PEM format).
	"""
	# Load the recipients pubkey from a PEM file
	with open(recipientKeyfile, 'rb') as f:
		recipientKey = RSA.import_key(f.read())

	# Encrypt the message with AES-GCM using a newly selected key
	messageKey, ctext = _aesEncrypt(message)

	# Encrypt the message key and prepend it to the ciphertext
	cipher = PKCS1_OAEP.new(recipientKey)
	encMsg = cipher.encrypt(messageKey) + ctext

	# Format the message into JSON
	return createJee(recipientKey, encMsg)

def publicKeyDecrypt(privkeyFile, jee):
	"""
	Decrypts an encrypted message with a private (RSA) key.
	Returns: (message, err)
	"""
	privkey = None
	with open(privkeyFile, 'rb') as f:
		privkey = RSA.import_key(f.read())

	# Verify that this is a private key
	if not privkey.has_private():
		return (None, publicKeyDecryptError)

	# Verify the JEE and extract the encrypted message
	encMsg, err = decodeAndVerifyJee(privkey.publickey(), jee)
	if err:
		return (None, err)

	# Separate the encrypted message key from the symmetric-encrypted portion.
	encKey, ctext = encMsg[:encMsgKeyBytes], encMsg[encMsgKeyBytes:]

	# Recover the message key
	msgKey = PKCS1_OAEP.new(privkey).decrypt(encKey)

	# Recover the underlying message
	try:
		return (_aesDescrypt(msgKey, ctext), None)
	except ValueError:
		return (None, decryptionFailedError)

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
		"pk_fp": b64encode(pkFingerprint(pubkey)),
		"enc_msg": b64encode(encMsg)
	}
	return json.dumps(env)

def decodeAndVerifyJee(pubkey, jsstxt):
	"""
	Parses and verifies a JSON encryption envelope against our default settings.
	Verifies the pubkey fingerprint against the pubkey provided.	
	Returns: (enc_data, error)
	"""
	env = {}
	try:
		env = json.loads(jsstxt)
	except ValueError as err:
		return (None, str(err))

	expectedFpB64 = b64encode(pkFingerprint(pubkey))

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

	return b64decode(str(env["enc_msg"])), None

def pkFingerprint(pubkey):
	"""
	Generates pubkey fingerprint using our fingerping technique:
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


def _aesEncrypt(message):
	"""
	Encrypts a message with a fresh key using AES-GCM. 
	Returns: (key, ciphertext)
	"""
	key = get_random_bytes(symmetricKeySizeBytes)
	cipher = AES.new(key, AES.MODE_GCM)
	ctext, tag = cipher.encrypt_and_digest(message)

	# Concatenate (nonce, tag, ctext) and return with key
	return key, (cipher.nonce + tag + ctext)

def _aesDescrypt(key, ctext):
	"""
	Decrypts and authenticates a ciphertext encrypted with with given key.
	"""
	# Break the ctext into components, then decrypt
	nonce,tag,ct = (ctext[:16], ctext[16:32], ctext[32:])
	cipher = AES.new(key, AES.MODE_GCM, nonce)
	return cipher.decrypt_and_verify(ct, tag)

#####
## Tests
##
def test_pkDecryptWithPubkey():
	message = "Three may keep a secret, if two of them are dead."
	jee = publicKeyEncrypt("./testkey-public.pem", message)
	recoveredMessage, err = publicKeyDecrypt("./testkey-public.pem", jee)
	assert(recoveredMessage is None)
	assert(err == publicKeyDecryptError)

def test_pkEncryptRoundTrip():
	message = "Three may keep a secret, if two of them are dead."
	jee = publicKeyEncrypt("./testkey-public.pem", message)
	print jee
	recoveredMessage, err = publicKeyDecrypt("./testkey-private.pem", jee)
	assert(err is None)
	assert(message == recoveredMessage)

def _test_createKeyPair():
	createPubkeyPair("./testkey")

def test_aesEncryptRoundTrip(): 
	message = "This is a long message that we want to verify can be decrypted exactly"
	key, ctext = _aesEncrypt(message)
	recoveredMessage = _aesDescrypt(key, ctext)
	assert(message == recoveredMessage)

def test_aesDetectsCtextError():
	message = "This message is expected to fail verification"
	key, ctext = _aesEncrypt(message)
	ctext = ctext[:20] + b'\x55' + ctext[21:]
	with pytest.raises(ValueError, message="MAC check failed"):
		recoveredMessage = _aesDescrypt(key, ctext)






