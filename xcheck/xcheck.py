"""
Command-line interface healthcare providers to report patient check-ins
"""
from lib import loadSettings, createPubkeyPair, processJee
import fire
import sys

class XCheckCli(): 
  def __init__(self):
    self.usage = \
    """
    Usage: xcheck [COMMAND] [ARGUMENTS]

    xcheck process CHECKIN_JEE 
        [--registry REGISTRY_CSV]
        [--privkey PATH_PRIVKEY_PEM]
    Decrypt and process an encrypted/hashed JEE file against a registry in CSV format. Matches are printed to STDOUT. 

    xcheck newkeys 
    Generates new public/private key pair in PEM format.
    """.strip()

  def help(self):
    """
    Print a usage string.
    """
    print self.usage

  def newkeys(self):
    settings = loadSettings()
    print "\nCreating key pair -- this may take several seconds"
    createPubkeyPair(basename="registry")

    printLines("Created new key pair: registry-public.pem, registry-private.pem",
      "To put into the default locations, run:\n",
      "mv registry-public.pem {}".format(settings["registryPubkeyfile"]),
      "mv registry-private.pem {}".format(settings["registryPrivkeyfile"])
      )

  def process(self, checkin_jee, registry=None, privkey=None,):
    """
    Process an uploade JEE file against a registry.
    """
    settings = loadSettings()
    registry = registry or settings["registryFile"]
    privkey = privkey or settings["registryPrivkeyfile"]

    err = processJee(jeeFile=checkin_jee, registryFile=registry, 
      privkeyFile=privkey)

    if err is not None:
        print "Error: {}".format(err)

def printLines(*args):
  print '\n'.join(list(args))

# Run!
if __name__ == '__main__':
  # Short-circuit Fire's error messages because they're unecessarily 
  # ugly and verbose
  # Check for "-h|--help" or no arguments and print the help message.
  if ("-h" in sys.argv or "--help" in sys.argv or "-help" in sys.argv or
    len(sys.argv) == 1):
    XCheckCli().help()
    sys.exit(1)

  # Hand-off to fire for argument processing
  fire.Fire(XCheckCli())
