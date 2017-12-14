"""
Command-line interface for xcheck
"""
from crypto import createPubkeyPair
from match import processRegistryUpdateFile, loadRegistry, processQueryFile
import fire
import sys

class Cli(): 
  usage = \
  """Usage: xcheck [COMMAND] [OPTIONS]

  Commands for providers:
  xcheck upload QUERY_CSV [--encryptOnly OUTPUT_FILE]

  Commands for registries:
  xcheck process QUERY1_JEE,QUERY2_JEE,... [--registry REGISTRY] [--privkey key-private.pem]
  xcheck update UPDATE_CSV [--registry REGISTRY]

  xcheck new_registry
  xcheck gen_registry_keys [KEYPATH]
  """

  def upload(self, query_csv, encryptOnly=None):
    """
    Encrypts and uploads QUERY_CSV to the registry service. If encryptOnly
    value 
    """

  # def process(self, queryfiles, registry=None,):
  #   print "Queryfile {}".format(query)

  def gen_registry_keys(self, keypath=None):
    """
    Generates a public/private RSA key pair for encrypting/decrypting query
    uploads. Files are written to KEYPATH-public.pem and KEYPATH-private.pem
    """
    # TODO: Load default value from settings.json
    basename = keypath or "registry"

    print "Generating new keys. This may take several seconds."
    createPubkeyPair(basename)

  def help(self):
    """
    Print a usage string.
    """
    print Cli.usage

  def process(self, queryfiles, registry=None, privkey=None):
    """
    Processes a list of encrypted query files against a protected registry.
    """
    # TODO: Load default paths from settings.json
    registry = registry or "samples/registry"
    privkey = privkey or "samples/registry-private.pem"

    # Load the registry
    registryEntries = loadRegistry(registry)

    for q in queryfiles.split(","):
      processQueryFile(queryJeefile=q, privkeyfile=privkey, 
        registry=registryEntries)

  def update(self, update_csv, registry=None):
    """
    Updates (or creates) a registry by adding entries from UPDATE_CSV.
    """
    # TODO: Load registry default from settings.json
    registry = registry or "samples/registry"
    n = processRegistryUpdateFile(update_csv, registry)
    print "Registry updated -- {} records added".format(n)

# Run!
if __name__ == '__main__':
  # Short-circuit Fire's error messages because they're unecessarily 
  # ugly and verbose
  # Check for "-h|--help" or no arguments and print the help message.
  if ("-h" in sys.argv or "--help" in sys.argv or "-help" in sys.argv or
    len(sys.argv) == 1):
    Cli().help()
    sys.exit(1)

  # Hand-off to fire for argument processing
  fire.Fire(Cli())
