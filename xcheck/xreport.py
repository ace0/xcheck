"""
Command-line interface healthcare providers to report patient check-ins
"""
# from crypto import createPubkeyPair
# from match import processRegistryUpdateFile, loadRegistry, processQueryFile
from lib import permuteCsv
import fire
import sys


class XReportCli(): 
  usage = \
  """Usage: xreport [COMMAND] [OPTIONS]

  Simple:

  xreport send CHECKIN_CSV 
    Hashes, encrypts, and uploads a CSV of patient check-in information
    using the values in settings.json


  Others:
  xreport protect CHECKIN_CSV 
      [--pubkey REG_PUBLIC_PEM] 
      [--out CHECKIN_JEE]
    Hashes and encrypts a CSV, but does not upload

  xreport upload CHECKIN_JEE
      [--sshkey SFTP_PRIVATE]
      [--server SFTP_ADDRESS]
    Uploads a JSON encrypted envelope (jee) to an SFTP service
  """

  def protect(self, checkin_csv, pubkey=None, out=None):
    """
    Read and verify a CSV; transform entries according to partial-matching
    rules; hash each entry with random salt; encrypt the dataset with 
    a public key and package the results as a JSON encrypted envelope 
    (jee file).
    """
    out = out or "./permute.csv"
    for row in permuteCsv(checkin_csv):
      print row

  def help(self):
    """
    Print a usage string.
    """
    print XReportCli.usage


# Run!
if __name__ == '__main__':
  # Short-circuit Fire's error messages because they're unecessarily 
  # ugly and verbose
  # Check for "-h|--help" or no arguments and print the help message.
  if ("-h" in sys.argv or "--help" in sys.argv or "-help" in sys.argv or
    len(sys.argv) == 1):
    XReportCli().help()
    sys.exit(1)

  # Hand-off to fire for argument processing
  fire.Fire(XReportCli())
