"""
Command-line interface for xcheck
"""
import fire

class Cli(): 
  usage = """
  Usage: xcheck [COMMAND] [OPTIONS]

  Commands for providers:
  xcheck upload QUERY_CSV

  Commands for registries:
  xcheck process [--registry REGISTRY] [--queryfiles QUERY1 QUERY2 ...]
  xcheck update UPDATE_CSV [--registry REGISTRY]

  xcheck new-registry
  xcheck gen-registry-keys
  """

  def upload(self, query_csv):
    """
    Encrypts and uploads QUERYFILE (*.csv) to a registry service
    """
    print "Queryfile {}".format(query)

  def process(self, query):
    print "Queryfile {}".format(query)

  def help(self):
    print Cli.usage

if __name__ == '__main__':
  fire.Fire(Cli())