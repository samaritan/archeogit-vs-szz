import yaml
from os import listdir
from os.path import isfile, join, dirname

# Change this to the path of the cloned *-vulnerabilties cves folder
CVES_DIR = dirname(r"C:\Users\Chres\Desktop\Development\Misc\struts-vulnerabilities\cves\\")


def get_all_cves():
    return [f for f in listdir(CVES_DIR) if isfile(join(CVES_DIR, f))]


def get_data(cve_filename):
    with open(CVES_DIR + "/" + cve_filename) as f:
        return yaml.safe_load(f)
