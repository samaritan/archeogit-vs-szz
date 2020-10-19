import logging

from . import base

logger = logging.getLogger(__name__)


class SZZ(base.BaseBlamer):
    def blame(self, sha):
        pass
