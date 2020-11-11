import logging
from archeogitvsszz import utilities

from joblib import delayed, Parallel

from .blamers import Archeogit, SZZ

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(self, vulnerabilities, repository):
        self._vulnerabilities = vulnerabilities
        self._repository = repository

    def analyze(self):
        csv_entries = Parallel(n_jobs=-1)(
            self.run_analysis(v) for v in self._vulnerabilities
        )

        # generate CSV
        self.write_to_csv(csv_entries)

    @delayed
    def run_analysis(self, cve_file):
        archeogit, szz = Archeogit(self._repository), SZZ(self._repository)
        vulnerability = self._vulnerabilities.get(cve_file)

        szz_contributors = szz.blame(vulnerability.fixes)
        szz_recall, szz_precision = \
            utilities.Calculation.get_recall_and_precision(
                szz_contributors, vulnerability.contributors
            )

        # archeogit blame
        archeogit_contributors = []

        # archeogit recall, precision
        archeogit_recall = []
        archeogit_precision = []

        return (
            vulnerability.cve,
            ','.join(vulnerability.fixes),
            ','.join(vulnerability.contributors),
            ','.join(szz_contributors), szz_precision, szz_recall,
            ','.join(archeogit_contributors), archeogit_precision,
            archeogit_recall
        )

    def write_to_csv(self, entries):
        fields = ["cve", "fix_commits", "ground_truth", "szz_contributors", "szz_precision", "szz_recall", "archeogit_contributors", "archeogit_precision", "archeogit_recall"]
        entries.insert(0, fields)
        utilities.CSV.write(entries, 'data.csv')
