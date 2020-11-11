import logging
from os import listdir
from os.path import isfile, join

from . import utilities

logger = logging.getLogger(__name__)


class Vulnerabilities:
    def __init__(self, path):
        self._path = path
        self._cve_path = join(path, "cves")
        self._cves = self.get_all_file_names()
        self._index = 0

    def __iter__(self):
        return iter(self._cves)

    def __next__(self):
        self._index += 1
        return self._cves[self._index]

    def get(self, cve_file):
        return utilities.YAML.read(join(self._cve_path, cve_file))

    def get_all_file_names(self):
        onlyfiles = [f for f in listdir(self._cve_path) if isfile(join(str(self._cve_path), f))]
        logger.debug(onlyfiles)
        return onlyfiles

    @staticmethod
    def get_fix_commits(cve):
        fix_commits = []
        for fix in cve["fixes"]:
            if fix["commit"] is not None:
                fix_commits.append(fix["commit"])
        return fix_commits

    @staticmethod
    def has_fix(cve):
        for fix in cve["fixes"]:
            if fix["commit"] is not None:
                return True
        return False

    @staticmethod
    def get_ground_truth(cve):
        vcc_commits = set()
        for fix in cve["vccs"]:
            if fix["commit"] is not None:
                vcc_commits.add(fix["commit"])
        return vcc_commits

