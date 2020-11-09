import logging

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(self, vulnerabilities, archeogit, szz):
        self._vulnerabilities = vulnerabilities
        self._archeogit = archeogit
        self._szz = szz

    def analyze(self):
        self._archeogit.blame("85812fb9bbf1dc8358d0352157142ec3131e015b")
