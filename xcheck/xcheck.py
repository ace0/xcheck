"""
Command-line interface for xcheck
"""
import fire
from crypto import createPubkeyPair
from match import processRegistryUpdateFile

class Cli(): 
  usage = """
  Usage: xcheck [COMMAND] [OPTIONS]

  Commands for providers:
  xcheck upload QUERY_CSV

  Commands for registries:
  xcheck process [--registry REGISTRY] [--queryfiles QUERY1 QUERY2 ...]
  xcheck update UPDATE_CSV [--registry REGISTRY]

  xcheck new-registry
  xcheck gen_registry_keys [KEYPATH]
  """

  def update(self, update_csv, registry=None):
    """
    Updates (or creates) a registry by adding entries from UPDATE_CSV.
    """
    # TODO: Load registryfile default from settings.json
    registry = registry or "samples/registry"
    processRegistryUpdateFile(update_csv, registry)
    print "Registry updated"

  def upload(self, query_csv):
    """
    Encrypts and uploads QUERYFILE (*.csv) to a registry service
    """
    print "Queryfile {}".format(query)

  def process(self, query):
    print "Queryfile {}".format(query)

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
    print Cli.usage

if __name__ == '__main__':
  fire.Fire(Cli())