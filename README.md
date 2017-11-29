# xCheck
xCheck manages a protected registry of names and birthdates and permits the registry to be updated and queried securely. A single organization manages a registry identifying information (name, birthdate) for patients that have tested positive for an infectious disease. Separate health care providers submit queries to the registry that contain identifying information for patients that have recently visited a facility. The regsitry receives these queries, checks them against the registry, and identifies any matches. If a match is found the registry can notify the provider. Notification is outside the scope of xCheck--xCheck takes care of securing the registry, queries, and performs matching logic.

xCheck corrects for some common typographical and date reporting errors. For name matching, corrections are: name inversion (switching first-last names), ignoring capitalization differences and whitespace differences ("von halderan" and "VonHalderan" are name matches). If a name match is found and an exact birthdate match is found, xCheck reports a "complete match". If no complete match is found, but a name mathc is present, xCheck finds "partial matches". A partial match is a name match (including corrections described above) and a birthdate with one of the following corrections: day-month swap, +-1 day-of-month, +-10 years.

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

## Establishing your own registry
xCheck is free, open-source software. These instructions outline how to run and manage your own registry.
- Setup an SFTP server that use public key authentication (not password authentication
- User accounts on the SFTP server should have only PUT permissions
- Fork this repository and clone it to the SFTP server
- Use `newregistry` command to establish a new registry or edit `settings.json` for manual configuration

Example:
```
$ xcheck newregistrykey 
Delete previous registry, settings, and keys? [y/N] y
sftp server address [127.0.0.1:23]: 123.456.8.5:23
Path to sftp server uploads [~/sftp/]: ~/var/data/
sftp server host key [~/.ssh/sftp.pub]: 
Generating new registry keys (this takes a few seconds)
Done! See settings.json to make changes
```

## Security of xCheck
xCheck uses a combination of techniques to protect registry entries and queries uploaded to the registry.

#### Enrollment of authorized users for query uploads
Query uploads can only be performed by authorizes users. A healthcare provider that wishes to enroll creates an SSH keypair and emails with an enrollment request to the registry operator. The registry operator confirms the identity of the healthcare provider (through phone call and/or personal references), and adds the provider's public key to the SFTP server's list of authorized users.

#### Upload authorized by public key authentication
Public key authentication protects SFTP connections. It is more secure and less prone to error or secret compromise than password-based authentication.

#### Uploads are protected in-transit
SFTP uses the SSH protocol to protect communications with strong cryptography.

#### Patient information in queries protected
Patient information (name and birthdate) are further protected using public key encryption. Providers can encrypt query files using the registry's publc key.

LEFT OFF DESCRIBING SECURITY FEATURES

