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

### Convert a registry CSV into hashes
```
python xcheck.py hash samples/registry.csv
```

### Create a hashed and encrypted file for a site
```
python xreport.py protect samples/checkin.csv --pubkey samples/testkey-public.pem
```

### Decrypt site file, match it against the hashed registry, and report exact or partial matches
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
- Clone this registry (use the clone button on GitHub) to make your own copy.
- Clone that registry unto your desktop computer.
- Create new keys

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

On Windows, drag-and-drop files into the directories above. The public key will be in the `settings/` directory and will become part of the public repository. The private key is outside the repository so that it doesn't become public.

Commit these changes, push them to GitHub, and check GitHub to make sure the public key is there.

# Instructions for testing, debugging, and validation

Turn on debugging for site reporting and registry matching:
- Open `xcheck/lib.py`
- Change `debug=True` for each of the following functions:

```
def protectEntry(name1, name2, birthdate, debug=True):
```

```
def processReports(inputfile, outfile, recipientKeyfile, debug=True):
```

Run these commands

## Build a hashed registry:
```
python xcheck.py hash samples/registry.csv
```

Expected output shows the records just before they are hashed.
```
MALIKARHOADES1910-05-20
RHOADESMALIKA1910-05-20
MALIRHOADES1910-05-20
RHOAMALIKA1910-05-20
MALIKARHOADES1910-05-21
MALIKARHOADES1910-05-19
LEOLAWEEKS1920-05-20
WEEKSLEOLA1920-05-20
LEOLWEEKS1920-05-20
WEEKLEOLA1920-05-20
LEOLAWEEKS1920-05-21
LEOLAWEEKS1920-05-19
YEVETTEDORTCH1930-05-20
DORTCHYEVETTE1930-05-20
YEVEDORTCH1930-05-20
DORTYEVETTE1930-05-20
YEVETTEDORTCH1930-05-21
YEVETTEDORTCH1930-05-19
CANTINARAYFORD1940-05-10
RAYFORDCANTINA1940-05-10
CANTRAYFORD1940-05-10
RAYFCANTINA1940-05-10
CANTINARAYFORD1940-10-05
CANTINARAYFORD1940-05-11
CANTINARAYFORD1940-05-09
BENITAHARWELL1950-05-20
HARWELLBENITA1950-05-20
BENIHARWELL1950-05-20
HARWBENITA1950-05-20
BENITAHARWELL1950-05-21
BENITAHARWELL1950-05-19
PHYLISBRAVO1960-07-05
BRAVOPHYLIS1960-07-05
PHYLBRAVO1960-07-05
BRAVPHYLIS1960-07-05
PHYLISBRAVO1960-05-07
PHYLISBRAVO1960-07-06
PHYLISBRAVO1960-07-04
JOSLYNMARTELL1970-05-20
MARTELLJOSLYN1970-05-20
JOSLMARTELL1970-05-20
MARTJOSLYN1970-05-20
JOSLYNMARTELL1970-05-21
JOSLYNMARTELL1970-05-19
CALLIESWEET1980-05-20
SWEETCALLIE1980-05-20
CALLSWEET1980-05-20
SWEECALLIE1980-05-20
CALLIESWEET1980-05-21
CALLIESWEET1980-05-19
SONDRAHARLAN1990-05-20
HARLANSONDRA1990-05-20
SONDHARLAN1990-05-20
HARLSONDRA1990-05-20
SONDRAHARLAN1990-05-21
SONDRAHARLAN1990-05-19
LOCKETTANGLA2000-05-20
ANGLALOCKETT2000-05-20
LOCKANGLA2000-05-20
ANGLLOCKETT2000-05-20
LOCKETTANGLA2000-05-21
LOCKETTANGLA2000-05-19
Created protected registry: settings/protected-registry
```

## Build a hashed-and-encrypted file
```
python xreport.py protect samples/checkin.csv --pubkey samples/testkey-public.pem
```

Output shows the records just before they are hashed and then shows the hashes before they are encrypted:
```
BENITAHARWELL1950-05-20
HARWELLBENITA1950-05-20
BENIHARWELL1950-05-20
HARWBENITA1950-05-20
DORTCHYEVE1930-05-20
YEVEDORTCH1930-05-20
DORTYEVE1930-05-20
YEVEDORTCH1930-05-20
BRAVOPHYLIS1960-05-07
PHYLISBRAVO1960-05-07
BRAVPHYLIS1960-05-07
PHYLBRAVO1960-05-07
ANGLALOCKETT2010-05-20
LOCKETTANGLA2010-05-20
ANGLLOCKETT2010-05-20
LOCKANGLA2010-05-20
SWEETCALLIE1980-05-20
CALLIESWEET1980-05-20
SWEECALLIE1980-05-20
CALLSWEET1980-05-20
MARTELLJOSLYN1970-05-20
JOSLYNMARTELL1970-05-20
MARTJOSLYN1970-05-20
JOSLMARTELL1970-05-20
NOENTRYTEST2000-05-20
TESTNOENTRY2000-05-20
NOENTEST2000-05-20
TESTNOENTRY2000-05-20
True,site-082,6WN4BC5uojFiP4BZDivhNAtF8hTtOvS53B6M0CDOE-qLbUnILZ13ETcwPsgWr9BrmX1yPz930AoFeY9peoE_TA==
True,site-082,MW4lCTShPIajkDCDFzcN1s_21LIftOks98gaxjsdXhm-3_Hz4U03WUFT2no_urxsdDAcU7PiUvw7PzjVSPJXIA==
False,site-082,Ym6K40XBLPCwTaxwd4VipcO2krDx6SiQuFJOpKrgeHXmi1aJTPK-LqddS94InmrlARSc2ZPMvHnF54QzQDrEFg==
False,site-082,hzUVxxb6NWbCwC7XjwBIFwSPldJWpPygNEVzy_yKo6qQ0J7JANfYnCUKNQtxGWW8s3Nbsj-FSFNKk9vInQkEBQ==
True,site-082,kTqnNOinejTLWNPBgGPG4fM-gBJ0LccYvFbcGD3v9Qrof4Ta367V7-uMhpU2QMeT-_lWhy96IgZL8hipM27epw==
True,site-082,RrsJuJxyTiXy5JInh7DbQsPvVEe5h4YX4x4uKIs_sjHcwZtUmMqUQai80KzvQGn7p2KZQQoOYKzWaLYuVHyHxA==
False,site-082,ig7XML0gpDBUAEPnqnFnQgrOX_UXES346yBfrj86J0K3G449iJDnI_nn7u7UsEbCPTq4uJgL_j5Xb7wBUFSNnA==
False,site-082,RrsJuJxyTiXy5JInh7DbQsPvVEe5h4YX4x4uKIs_sjHcwZtUmMqUQai80KzvQGn7p2KZQQoOYKzWaLYuVHyHxA==
True,site-082,T4CySnX-YB-DKujkQJYVJFG4xcuOrOIigTOdB-XxxGyDcgffdjAxD9PFHA7wFpA8pJkHBadLo9uDbMJVH4O7bA==
True,site-082,SGYIpjdWZOrsKOQ4cXrMLkFWtP5CabTtGZSJqL9_torpMMGJRDR9Rmc36M_sYE178RIcaQxlmIrs8NEwcg8mxQ==
False,site-082,Awj-qWGmB4eaPjPHFj86rnyPBzmu_leAnOjKju4QnR620RDOOjBQVjFFa9OZmPtE-i93gYP8OGsLlUhA3U4hwA==
False,site-082,mxznvgSphfjB2hG2-Vb5jQowHQycmFglYpqGa0y_aUhyXCvzpXJNP1F0Qw0SP3C1b7R-zviLo8ecufYDXIJZSA==
True,site-082,VgvEnpKBmM0wiDTiKVYBQU9fuvXK3oQqOphOdYbLWLd8uc4fO7SbQ23BsZFom2UKmG60KNmAHFZAIHzMovachA==
True,site-082,yviniU339ZsCNf_AFn8hzDEfDcqtjgMTkoDfB2tvGVz5xnIWRbAnbTqwx0quB3sfNh1MeFe5NH-iFZFWdzNUsA==
False,site-082,xanZOb2MGwcix8rWEHkcCOPWNDHOqN0OhEuNYCLXeHmj26PIdJeu5KX0-BJSFnmhGEK3IUr1jAP8lII54nzAhg==
False,site-082,FztEFOQDtWHLDH54tSktDnQAI04rkk3EqyWcOFRMD6wNwUreVAXROQ2ACRWBekLRexRHOthLrQtk_p3EtZtj6w==
True,site-082,lh3ggZ0PhQk_5rqMLCeCJO9FNXBDzFk5N4rjpm38PSgrPwsBShT-Au0F3LgLMxxQQr1bQL0YhCZmEAo7JhsUhg==
True,site-082,gKQuCeQAv7hzmO9gEuBSEsJcjXT0SnU2kJ1BZV1jghUUBigIcBI3GG39cQHXml11DfcRdNrH4RfW5ehPJq9LJw==
False,site-082,VF14o1xnLWtP1aiBQGt238OZ72itGs6h0h4Z6QLxYd0DMEJOg-2L0mIc7wIO17-IGnpRHSeOZkbYBX5skIOwwQ==
False,site-082,Ks65tfouDeT_xfB_cp3D0lg2CSYcH5vm-QUiicn8gRSJiEjOig1Eqhxf5Vcp6I4UyeVG9ey25YkKIuvBsENkeg==
True,martell,ondOgGa2E3XZLNuVVRZR-JDzrrxQEFj8eoYlEDo4GiFVO9mNk1djfe9ykKQ5K4VU40N4ZvhY2Tibk_nTHn5fBw==
True,martell,UgODditUSUs6pRh87XZh9NrL9ad0yL6ImLQM9t4JFFWnMSE2DlzF4bvj4Nyn0GqkZSPXQrXGVSu-RbgpzffktA==
False,martell,x9729fYYU5IC8L34RkPhaYUwVg0jPkY8zVIND80MAP24Cr7xBFrlJQiAm2w_W1aJkEGZCOVk8IIdpFHNvscp8w==
False,martell,JkFFgfeI1fBVF7rPPoCUIuwlxgMundvxiz9wltUrenkrL-048O0WF9wV1hQjKauCoNUBwrTR1ormNyPdY7NX7Q==
True,site-082,3JwIUz1MdRhJzGrZbuMY5tGCwGUhY1H2bMJzHAFfNx8SSFX3edSmlHBH2WpoFDh0fgLKq7UzdPYvU3x0BhhQMw==
True,site-082,_HtnP9nJfJz9FJ63Nwf_qFw4UkNQM7k59CypnH6q0I7D7TgV1_LPOktwK1n_fRCg9VYi-2CB6FqrHzax-DvxKw==
False,site-082,2oyz0Yq4PbnVlek0WPzhgVbx8tyA8GtOeT5vIcSt7vR6Ls5qTF5B0an4JliqgOjlGjwh19e4OzTxP2rbYzmqkw==
False,site-082,_HtnP9nJfJz9FJ63Nwf_qFw4UkNQM7k59CypnH6q0I7D7TgV1_LPOktwK1n_fRCg9VYi-2CB6FqrHzax-DvxKw==
Check-in file 'samples/checkin.csv' processed. Created encrypted file './protected.jee'
```
