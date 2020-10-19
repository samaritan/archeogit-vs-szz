import logging

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(self, vulnerabilities, archeogit, szz):
        self._vulnerabilities = vulnerabilities
        self._archeogit = archeogit
        self._szz = szz

    def analyze(self):
        pass
