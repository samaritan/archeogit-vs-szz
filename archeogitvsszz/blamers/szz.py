import logging
import subprocess
import os
import json
import shutil

from . import base

logger = logging.getLogger(__name__)


class SZZ(base.BaseBlamer):

    def blame(self, sha):

        # values for root key and dates are irrelevant, but need to be correctly formatted
        issues_list_dict = {
            "JENKINS-48080": {
                "commitdate": "2021-07-1 00:37:08 +0100",
                "creationdate": "2021-12-03 20:08:14 +0000",
                "hash": sha,
                "resolutiondate": "2021-12-03 20:08:14 +0000"
            }
        }

        with open('issue_list.json', 'a') as file:
            json.dump(issues_list_dict, file)

        result = subprocess.run(['java', '-jar', 'szz_find_bug_introducers-0.1.jar', '-i', 'issue_list.json', '-r', str(self._repository.path)],
                                stdout=subprocess.PIPE)

        with open('results/result0/fix_and_introducers_pairs.json') as json_file:
            data = json.load(json_file)

        contributors = self.get_contributors(data)

        print("Contributors: ")
        print(contributors)

        self.remove_files()

        result.stdout.decode('utf-8')

        return contributors

    def get_contributors(self, pairs):
        contributors = []
        for pair in pairs:
            if pair[1] not in contributors:
                contributors.append(pair[1])
        return contributors

    def remove_files(self):
        os.remove('issue_list.json')
        shutil.rmtree("results")
        shutil.rmtree("issues")


