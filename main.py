import logging
import time


from logging.config import dictConfig

from archeogitvsszz import utilities
from archeogitvsszz import Analyzer, Archeogit, CLI, Repository, SZZ, \
                           Vulnerabilities


def _configure_logging(configuration):
    dictConfig(configuration['logging'])


def main():
    cli = CLI()
    arguments = cli.get_arguments()

    configuration = utilities.YAML.read(arguments.config_file)
    _configure_logging(configuration)
    logger = logging.getLogger('archeogitvsszz')

    repository = Repository(arguments.repository)
    vulnerabilities = Vulnerabilities(arguments.vulnerabilities)

    archeogit = Archeogit(repository)
    szz = SZZ(repository)

    analyzer = Analyzer(vulnerabilities, archeogit, szz)

    start = time.time()
    analyzer.analyze()
    elapsed = time.time() - start
    logger.info('Analysis took %.2f seconds', elapsed)


if __name__ == '__main__':
    main()
