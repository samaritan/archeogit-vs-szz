import logging

from . import base

logger = logging.getLogger(__name__)


class Archeogit(base.BaseBlamer):
    def blame(self, sha):
        pass
