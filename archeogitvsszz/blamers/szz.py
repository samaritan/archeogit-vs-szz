import logging
import subprocess
import os
import json
import tempfile

from . import base
from archeogit.repository import Repository

logger = logging.getLogger(__name__)
szz_dir = os.path.abspath("szz_find_bug_introducers-0.1.jar")
root_dir = os.path.dirname(os.path.abspath(__file__))


class SZZ(base.BaseBlamer):
    def __init__(self, repository, szz_depth):
        super().__init__(repository)
        self._repository = Repository(str(self._repository.path))
        self._szz_depth = szz_depth

    def blame(self, shas):
        # values for root key and dates are irrelevant, but need to be correctly formatted
        issues_list_dict = {}
        for sha in shas:
            issues_list_dict[sha] = {
                "commitdate": "2021-07-1 00:37:08 +0100",
                "creationdate": "2021-07-1 00:00:00 +0000",
                "hash": sha,
                "resolutiondate": "2021-12-03 20:08:14 +0000"
            }

        logger.debug(issues_list_dict)

        with tempfile.TemporaryDirectory() as temp_path:
            os.chdir(temp_path)

            with open('issue_list.json', 'a') as file:
                json.dump(issues_list_dict, file)

            result = subprocess.Popen(['java', '-jar', szz_dir, '-i', 'issue_list.json', '-r', str(self._repository.path), "-d", self._szz_depth],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            result.wait()

            with open('results/fix_and_introducers_pairs.json') as json_file:
                data = json.load(json_file)

            os.chdir(root_dir)

        contributors = self.get_contributors(data)

        logger.debug('Contributors %s', contributors)
        return contributors

    @staticmethod
    def get_contributors(pairs):
        contributors = set()
        for pair in pairs:
            if pair[1] not in contributors:
                contributors.add(pair[1])
        return contributors



