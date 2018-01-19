# xCheck
xCheck permits membership checking of demographic information against a registry. xCheck uses cryptographic hashing to protect demographic informatio and public key encryption to protect uploads sent to the registry. xCheck also accounts for common reporting mistakes in demographic information: name inversion (switching the first and last name), reported birthdates that are a close, but not perfect match. xCheck handles these partial-matching techniques through name canonicalization and submitting partial-matching records to the registry.

## Quickstart for healthcare providers to submit demographic information to the registry

### Install prerequisites and xCheck
xCheck requires python 2.7 

Windows users may find Anaconda useful: https://anaconda.com/download
On Windows, the commands below can be run from the Anaconda Prompt.

Install Python libraries.
MacOS + Linux, and Windows from the Anaconda Prompt.
```
# Install python libraries
pip install pycryptodome
pip install pytest
pip install fire

# Download xCheck and run tests
git clone git@github.com:ace0/xcheck.git
cd xcheck/xcheck
pytest
```

### Build an encrypted test file
```
python xcheck.py process protected.jee \
	--registry samples/registry.csv \
	--privkey samples/testkey-private.pem \
	--pubkey samples/testkey-public.pem
```

### Compare the encrypted test file against a demo registry
```
python xcheck.py process protected.jee \
    --registry samples/registry.csv \
    --privkey samples/testkey-private.pem \
    --pubkey samples/testkey-public.pem
```
Expected output:
```
Found exact match: Benita, Harwell, 1950-05-20
Found partial match: Phylis, Bravo, 1960-05-20
Found partial match: Angla, Lockett, 2000-05-20
Processed 4 checkin entries against 10 registry entries
```
