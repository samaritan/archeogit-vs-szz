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

        # generate CSV
        self.write_to_csv(csv_entries)

    def run_analysis(self, cve_file, szz_precisions, szz_recalls, csv_entries):
        cve = self.get_cve(cve_file)
        fix_commits = self._vulnerabilities.get_fix_commits(cve)
        ground_truth = self._vulnerabilities.get_ground_truth(cve)

        szz_contributors = self._szz.blame(fix_commits)
        szz_results = utilities.Calculation.get_recall_and_precision(szz_contributors, ground_truth)

        # archeogit blame
        archeogit_contributors = []

        # archeogit recall, precision
        archeogit_recall = []
        archeogit_precision = []

        csv_entry = self.create_csv(cve["CVE"], fix_commits, ground_truth, szz_contributors, szz_results[1], szz_results[0], archeogit_contributors, archeogit_precision, archeogit_recall)
        csv_entries.append(csv_entry)

    def create_csv(self, cve, fix_commits, ground_truth, szz_contributors, szz_precision, szz_recall, archeogit_contributors, archeogit_precision, archeogit_recall):
        return [cve, str(fix_commits), list(ground_truth), list(szz_contributors), szz_precision, szz_recall, archeogit_contributors, archeogit_precision, archeogit_recall]

    def write_to_csv(self, entries):
        fields = ["cve", "fix_commits", "ground_truth", "szz_contributors", "szz_precision", "szz_recall", "archeogit_contributors", "archeogit_precision", "archeogit_recall"]
        entries.insert(0, fields)
        utilities.CSV.write(entries, 'data.csv')

    def get_cve(self, cve_file):
        return utilities.YAML.read(join(self._vulnerabilities._cve_path, cve_file))
