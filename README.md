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


### Process a registry 
```
python xcheck.py hash samples/registry.csv
```

### Build an encrypted test file
```
python xreport.py protect samples/checkin.csv --pubkey samples/testkey-public.pem
```

### Compare the encrypted test file against a demo registry
```
python xcheck.py process protected.jee --privkey samples/testkey-private.pem
```

Expected output:
```
Found exact match: 6WN4BC5uojFiP4BZDivhNAtF8hTtOvS53B6M0CDOE-qLbUnILZ13ETcwPsgWr9BrmX1yPz930AoFeY9peoE_TA==
Found partial match: DhkR2-7K1IjSlpvc9Mp4yeVlB0Gs2AGlhHWQd-VVuLWdTwCWV3ClLeIFA91Snuey0YN6k5omL449zK-aruJWFw==
Found partial match: CwMOlE7spz9OdPCVN6UyoTb4mkri9Ov5RLs8QbXV2Bfmdpl-Irgjmwk6eWVKC9zQOFrZpsod4uJNhshA77t99Q==
Processed 4 checkin entries against 10 registry entries
```