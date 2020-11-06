import logging
import time
from multiprocessing import Manager, Pool, Array
from functools import partial

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

    manager = Manager()
    szz_precisions = manager.list()
    szz_recalls = manager.list()
    archeogit_precisions = manager.list()
    archeogit_recalls = manager.list()

    pool = Pool()

    start = time.time()
    func = partial(analyzer.analyze, szz_precisions=szz_precisions, szz_recalls=szz_recalls, archeogit_precisions=archeogit_precisions, archeogit_recalls=archeogit_recalls)
    pool.map(func, all_files)
    elapsed = time.time() - start
    logger.info('Analysis took %.2f seconds', elapsed)
    print(round(sum(szz_precisions) / len(szz_precisions), 4))
    print(round(sum(szz_recalls) / len(szz_recalls), 4))
