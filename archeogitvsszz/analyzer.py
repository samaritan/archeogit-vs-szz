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
        self.write_to_csv(filter(lambda i: i is not None, csv_entries))

    @delayed
    def run_analysis(self, cve_file):
        vulnerability = self._vulnerabilities.get(cve_file)

        if not vulnerability.fixes:
            return None

        archeogit, szz = Archeogit(self._repository), SZZ(self._repository)
        szz_contributors = szz.blame(vulnerability.fixes)
        szz_recall, szz_precision = \
            utilities.Calculation.get_recall_and_precision(
                szz_contributors, vulnerability.contributors
            )
        archeogit_contributors = archeogit.blame(vulnerability.fixes)
        archeogit_recall, archeogit_precision = \
            utilities.Calculation.get_recall_and_precision(
                archeogit_contributors, vulnerability.contributors
            )

        return (
            vulnerability.cve,
            ','.join(vulnerability.fixes),
            ','.join(vulnerability.contributors),
            ','.join(szz_contributors), szz_precision, szz_recall,
            ','.join(archeogit_contributors), archeogit_precision,
            archeogit_recall
        )

    def write_to_csv(self, entries):
        header = [
            "cve", "fix_commits", "ground_truth", "szz_contributors",
            "szz_precision", "szz_recall", "archeogit_contributors",
            "archeogit_precision", "archeogit_recall"
        ]
        utilities.CSV.write(entries, 'data.csv', header=header)
