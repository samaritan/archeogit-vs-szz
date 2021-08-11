import logging
from archeogitvsszz import utilities

from joblib import delayed, Parallel

from .blamers import Archeogit, SZZ

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(self, vulnerabilities, repository, szz_depth):
        self._vulnerabilities = vulnerabilities
        self._repository = repository
        self._szz_depth = szz_depth

    def analyze(self, path):
        analysis = Parallel(n_jobs=-1)(
            self.run_analysis(v) for v in self._vulnerabilities
        )
        analysis = (filter(lambda i: i is not None, analysis))
        header = [
            "cve", "fix_commits", "ground_truth", "szz_contributors",
            "szz_precision", "szz_recall", "archeogit_contributors",
            "archeogit_precision", "archeogit_recall"
        ]
        analysis = sorted(analysis, key=lambda i: i[0])
        utilities.CSV.write(analysis, path, header=header)

    @delayed
    def run_analysis(self, cve_file):
        vulnerability = self._vulnerabilities.get(cve_file)

        if vulnerability is None or not vulnerability.fixes or \
                not vulnerability.contributors:
            return None

        archeogit, szz = Archeogit(self._repository), SZZ(self._repository, self._szz_depth)
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
