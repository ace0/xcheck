# xCheck
xCheck manages a protected registry of names and birthdates and permits the registry to be updated and queried securely. xCheck is designed to store infectious disease reports in a protected state (using an iterated cryptographic hash function and a local secret). Queries against the registry consist of a CSV file of patient names and birthdates. These are encrypted under a public key for the registry and transferred to the registry via secure file transfer protocol (SFTP).

## Quickstart for healthcare providers to query the registry
### Enroll with with registry
Generate an SSH key pair and send an enrollment request to the registry: TO-BE-UPDATED `enroll@cchs.org`

MacOS:
```
ssh-keygen -t ecdsa -N "" -f ~/.ssh/registry-upload
cat ~/.ssh/registry-upload.pub | pbcopy
```

Send an email to `enroll@cchhs.org` and paste the public key from the last command into the email. The email message should also contain the name of the healthcare provider and telephone contact information so the registry can confirm the healthcare providers enrollment is approriate.

### Install prerequisites and xCheck
xCheck requires python 2.7+

Install Python libraries.
MacOS + Linux:
```
# Install python libraries
sudo -H pip install pycryptodome
sudo -H pip install pytest

# Download xCheck and run tests
git clone git@github.com:ace0/xcheck.git
cd xcheck
py.test *.py
```

Upload a test query
```
echo "name1,name2,birthdate" > testupload.csv
echo "sample,sample,2009-05-01" >> testupload.csv
xcheck upload ./testupload.csv
```

