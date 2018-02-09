"""
Command-line interface used by a registry operator to create protected
registry from demographic information and process encrypted uploads 
and match them against the registry.
"""
from lib import (loadSettings, createPubkeyPair, processJee, processRegistry,
  printLines)
import fire
import platform, sys

class XCheckCli(): 
  def __init__(self):
    self.usage = \
    """
    Usage: xcheck [COMMAND] [ARGUMENTS]

    xcheck hash REGISTRY_CSV
      [--output PROTECTED_REGISTRY] 
    Process a registry with demographic information in CSV format. Hash each entry and write to a new file.

    xcheck process PROTECTED_JEE 
        [--registry PROTECTED_REGISTRY]
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

    mv = moveCmd()
    printLines("Created new key pair: registry-public.pem, registry-private.pem",
      "To put into the default locations, run:",
      "",
      "{} registry-public.pem {}".format(mv, settings["registryPubkeyfile"]),
      "{} registry-private.pem {}".format(mv, settings["registryPrivkeyfile"])
      )

  def hash(self, registry_csv, output=None):
    """
    Process a registry.csv into a new file file containing protected 
    (hashed) records.
    """
    settings = loadSettings()
    output = output or settings["registryFile"]
    processRegistry(registryCsvfile=registry_csv, registryOutfile=output)
    print "Created protected registry: {}".format(output)

  def process(self, protected_jee, registry=None, privkey=None,):
    """
    Process an uploade JEE file against a registry.
    """
    settings = loadSettings()
    registry = registry or settings["registryFile"]
    privkey = privkey or settings["registryPrivkeyfile"]

    err = processJee(jeeFile=protected_jee, protectedRegistryFile=registry, 
      privkeyFile=privkey)

    if err is not None:
        print "Error: {}".format(err)

def moveCmd():
  """
  Selects the correct move command. 
  For Windows/win32: "move"; 
  all others (and default): "mv"
  """
  if platform.system().lower().startswith("win"):
    return "move"
  else:
    return "mv"

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
