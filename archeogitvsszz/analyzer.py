import logging
from archeogitvsszz import utilities
from os.path import join

logger = logging.getLogger(__name__)

class Analyzer:
    def __init__(self, vulnerabilities, archeogit, szz):
        self._vulnerabilities = vulnerabilities
        self._archeogit = archeogit
        self._szz = szz

    def analyze(self, cve_file, szz_precisions, szz_recalls, archeogit_precisions, archeogit_recalls):
        print("Processing -------- " + cve_file)
        cve = self.get_cve(cve_file)
        fix_commits = self.get_fix_commits(cve)
        ground_truth = self.get_ground_truth(cve)

        szz_contributors = set()
        for fix_commit in fix_commits:
            result = self._szz.blame(fix_commit)
            szz_contributors.update(result)

        print("Fix Commits: " + str(fix_commits))
        print("Contributors: " + str(szz_contributors))
        print(len(szz_contributors))
        print("Ground Truth: " + str(ground_truth))

        precision = self.get_precision(szz_contributors, ground_truth)
        print("Precision: " + str(precision))
        recall = self.get_recall(szz_contributors, ground_truth)
        print("Recall: " + str(recall))

        szz_precisions.append(precision)
        szz_recalls.append(recall)


        # do same with archeogit

    def get_cve(self, cve_file):
        return utilities.YAML.read(join(self._vulnerabilities._cve_path, cve_file))

    @staticmethod
    def get_fix_commits(cve):
        fix_commits = []
        for fix in cve["fixes"]:
            if fix["commit"] is not None:
                fix_commits.append(fix["commit"])
        return fix_commits

    @staticmethod
    def has_fix(cve):
        for fix in cve["fixes"]:
            if fix["commit"] is not None:
                return True
        return False

    @staticmethod
    def get_ground_truth(cve):
        vcc_commits = []
        for fix in cve["vccs"]:
            if fix["commit"] is not None:
                vcc_commits.append(fix["commit"])
        return vcc_commits


    @staticmethod
    def get_recall(contributors, ground_truth):
        true_positives = 0
        for contributor in contributors:
            if contributor in ground_truth:
                true_positives += 1

        false_negatives = 0
        for contributor in ground_truth:
            if contributor not in contributors:
                false_negatives += 1

        if true_positives + false_negatives == 0:
            return 0.0

        recall = true_positives / float(true_positives + false_negatives)
        return recall

    @staticmethod
    def get_precision(contributors, ground_truth):
        true_positives = 0
        for contributor in contributors:
            if contributor in ground_truth:
                true_positives += 1

        false_positives = 0
        for contributor in contributors:
            if contributor not in ground_truth:
                false_positives += 1

        if true_positives + false_positives == 0:
            return 0.0

        precision = true_positives / float(true_positives + false_positives)
        return precision
