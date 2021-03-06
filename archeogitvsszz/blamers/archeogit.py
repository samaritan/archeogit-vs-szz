import logging

from archeogit import blame
from archeogit.repository import Repository

from . import base

logger = logging.getLogger(__name__)


class Archeogit(base.BaseBlamer):
    def __init__(self, repository):
        super().__init__(repository)
        self._repository = Repository(str(self._repository.path))

    def blame(self, shas):
        contributors = set()
        for sha in shas:
            contributors |= self._blame(sha)
        return contributors

    def _blame(self, sha):
        commit = self._repository.get(sha)
        contributors = blame.blame(self._repository, commit)
        return {m.sha for c in contributors.values() for m in c}
