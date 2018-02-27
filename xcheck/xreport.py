"""
Command-line interface healthcare providers to report patient check-ins
"""
from lib import processReports, loadSettings, noteError
import fire
import sys

class XReportCli(): 
  def __init__(self):
    self.usage = \
    """
    Usage: xreport protect CHECKIN_CSV 
        [--out PROTECTED_JEE]
        [--pubkey REG_PUBLIC_PEM]

    Hashes and encrypts a CSV so it can be uploaded to a registry.
    """.strip()

  def protect(self, checkin_csv, out=None, pubkey=None):
    """
    Read and verify a CSV; transform entries according to partial-matching
    rules; hash each entry with random salt; encrypt the dataset with 
    a public key and package the results as a JSON encrypted envelope 
    (jee file).
    """
    settings = loadSettings()
    out = out or settings["protectedFile"]
    pubkey = pubkey or settings["registryPubkeyfile"]

    try:
      processReports(inputfile=checkin_csv, recipientKeyfile=pubkey, 
        outfile=out)
    except Exception as e:
      noteError(srcfile=checkin_csv, errMsg=str(e), settings=settings, 
        cmd="xreport protect", terminate=True)

    print "Check-in file '{}' processed. Created encrypted file '{}'".format(
      checkin_csv, out)

  def help(self):
    """
    Print a usage string.
    """
    print self.usage

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
