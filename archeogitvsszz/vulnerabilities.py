import logging
from os import listdir
from os.path import isfile, join

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

    def get_all_file_names(self):
        onlyfiles = [f for f in listdir(self._cve_path) if isfile(join(str(self._cve_path), f))]
        print(onlyfiles)
        return onlyfiles
