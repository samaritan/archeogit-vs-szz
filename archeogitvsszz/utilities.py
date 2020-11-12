import csv
import logging

import yaml

logger = logging.getLogger(__name__)


class CSV:
    @staticmethod
    def write(data, path, header=None):
        with open(path, 'w', newline='') as file_:
            writer = csv.writer(file_)
            if header is not None:
                writer.writerow(header)
            writer.writerows(data)


class YAML:
    @staticmethod
    def read(path):
        with open(path, 'r') as file_:
            return yaml.safe_load(file_)


class Calculation:
    @staticmethod
    def get_recall_and_precision(contributors, ground_truth):
        true_positives = len(contributors & ground_truth)
        false_negatives = len(ground_truth - contributors)
        false_positives = len(contributors - ground_truth)

        recall = 0.0
        if true_positives + false_negatives != 0:
            recall = true_positives / float(true_positives + false_negatives)

        precision = 0.0
        if true_positives + false_positives != 0:
            precision = true_positives / float(true_positives + false_positives)

        return [recall, precision]


