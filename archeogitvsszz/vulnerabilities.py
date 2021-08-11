import logging
from os import listdir
from os.path import isfile, join

from . import utilities
from .models import Vulnerability

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
        def _get_commits(data, key):
            return {i['commit'] for i in data[key] if i['commit'] is not None}

        vulnerability = utilities.YAML.read(join(self._cve_path, cve_file))
        if vulnerability is not None:
            cve = vulnerability['CVE']
            fixes = _get_commits(vulnerability, 'fixes')
            contributors = _get_commits(vulnerability, 'vccs')
            return Vulnerability(cve=cve, fixes=fixes, contributors=contributors)
        return None

    def get_all_file_names(self):
        onlyfiles = [f for f in listdir(self._cve_path) if isfile(join(str(self._cve_path), f))]
        logger.debug(onlyfiles)
        return onlyfiles
