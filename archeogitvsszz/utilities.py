import logging

import yaml

logger = logging.getLogger(__name__)


class YAML:
    @staticmethod
    def read(path):
        with open(path, 'r') as file_:
            return yaml.safe_load(file_)
