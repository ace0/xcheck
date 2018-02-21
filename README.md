# xCheck
xCheck permits membership checking of demographic information against a registry. xCheck uses cryptographic hashing to protect demographic information and public key encryption to protect uploads sent to the registry. xCheck also accounts for common reporting mistakes in demographic information: name inversion (switching the first and last name), reported birthdates that are a close, but not perfect match. xCheck handles these partial-matching techniques through name canonicalization and submitting partial-matching records to the registry.

## Quickstart for health care providers to submit demographic information to the registry

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

### Pre-process a registry into protected records
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
  Reporting site: 75A
  Registry site:  50809

Found exact match: T4CySnX-YB-DKujkQJYVJFG4xcuOrOIigTOdB-XxxGyDcgffdjAxD9PFHA7wFpA8pJkHBadLo9uDbMJVH4O7bA==
  Reporting site: 6108-6653-73921
  Registry site:  site-091

Found partial match: VgvEnpKBmM0wiDTiKVYBQU9fuvXK3oQqOphOdYbLWLd8uc4fO7SbQ23BsZFom2UKmG60KNmAHFZAIHzMovachA==
  Reporting site: 765213
  Registry site:  site-082

Processed 4 uploaded records against 10 registry entries
```

## To create your own registry
Run the new keys command:
```
python xcheck.py newkeys
```

Expected output:
```
Creating key pair -- this may take several seconds
Created new key pair: registry-public.pem, registry-private.pem
To put into the default locations, run:

mv registry-public.pem settings/registry-public.pem
mv registry-private.pem ~/.ssh/registry-private.pem
```

On MacOS/Linux, run the move command:
```
mv registry-public.pem settings/registry-public.pem
mv registry-private.pem ~/.ssh/registry-private.pem
```

On Windows, drag-and-drop files into these directories.