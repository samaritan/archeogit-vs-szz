import logging

logger = logging.getLogger(__name__)


class BaseBlamer:
    def __init__(self, repository):
        self._repository = repository

    def blame(self, sha):
        pass
