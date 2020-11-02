import logging
import subprocess
import csv

from . import base

logger = logging.getLogger(__name__)


class Archeogit(base.BaseBlamer):
    def blame(self, sha):
        result = subprocess.run(['archeogit', 'blame', '--csv', str(self._repository.path), sha],
                                stdout=subprocess.PIPE)

        contributors = []
        for line in csv.DictReader(result):
            contributors.append(line['contributor'])
        print("Contributors: ")
        print(contributors)

        return contributors