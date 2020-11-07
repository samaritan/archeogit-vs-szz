import logging
from archeogitvsszz import utilities
from os.path import join
from multiprocessing import Manager, Pool, Array
from functools import partial

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(self, vulnerabilities, archeogit, szz):
        self._vulnerabilities = vulnerabilities
        self._archeogit = archeogit
        self._szz = szz

    def analyze(self):
        manager = Manager()
        szz_precisions = manager.list()
        szz_recalls = manager.list()
        csv_entries = manager.list()

        pool = Pool()

        func = partial(self.run_analysis, szz_precisions=szz_precisions, szz_recalls=szz_recalls,
                        csv_entries=csv_entries)
        pool.map(func, self._vulnerabilities)



        # do same with archeogit

    def run_analysis(self, cve_file, szz_precisions, szz_recalls, csv_entries):
        cve = self.get_cve(cve_file)
        fix_commits = self.get_fix_commits(cve)
        ground_truth = self.get_ground_truth(cve)

        szz_contributors = self._szz.blame(fix_commits)
        szz_precision = self.get_precision(szz_contributors, ground_truth)
        szz_recall = self.get_recall(szz_contributors, ground_truth)

        csv_entry = self.create_csv(fix_commits, ground_truth, szz_contributors, szz_precision, szz_recall)
        csv_entries.append(csv_entry)

        print(csv_entry)

    def create_csv(self, fix_commits, ground_truth, szz_contributors, szz_precision, szz_recall):
        return [str(fix_commits), str(ground_truth), str(szz_contributors), szz_precision, szz_recall]

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
        vcc_commits = set()
        for fix in cve["vccs"]:
            if fix["commit"] is not None:
                vcc_commits.add(fix["commit"])
        return vcc_commits

    @staticmethod
    def get_recall(contributors, ground_truth):
        true_positives = len(contributors & ground_truth)

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
        true_positives = len(contributors & ground_truth)

        false_positives = 0
        for contributor in contributors:
            if contributor not in ground_truth:
                false_positives += 1

        if true_positives + false_positives == 0:
            return 0.0

        precision = true_positives / float(true_positives + false_positives)
        return precision
