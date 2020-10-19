import logging

logger = logging.getLogger(__name__)


class Repository:
    def __init__(self, path):
        self._path = path

    @property
    def path(self):
        return self._path
