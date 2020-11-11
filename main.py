import logging
import time


from logging.config import dictConfig

from archeogitvsszz import utilities
from archeogitvsszz import Analyzer, Archeogit, CLI, Repository, SZZ, \
                           Vulnerabilities


def _configure_logging(configuration):
    dictConfig(configuration['logging'])


if __name__ == '__main__':
    cli = CLI()
    arguments = cli.get_arguments()

    configuration = utilities.YAML.read(arguments.config_file)
    _configure_logging(configuration)
    logger = logging.getLogger('archeogitvsszz')

    repository = Repository(arguments.repository)
    vulnerabilities = Vulnerabilities(arguments.vulnerabilities)
    all_files = vulnerabilities.get_all_file_names()

    archeogit = Archeogit(repository)
    szz = SZZ(repository)

    analyzer = Analyzer(vulnerabilities, archeogit, szz)

    start = time.time()
    analyzer.analyze()
    elapsed = time.time() - start
    logger.info('Analysis took %.2f seconds', elapsed)
