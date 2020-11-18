import argparse
import os
import pathlib


class CLI:
    def __init__(self):
        self._parser = argparse.ArgumentParser(
            description='Compare performance of archeogit and SZZ Unleashed.'
        )
        self._parser.add_argument(
            '--config-file', default='config.yml', type=pathlib.Path,
            help='Path to the configuration file. Default is config.yml.'
        )
        self._parser.add_argument(
            '--output-file', default='output.csv',
            help='Path to the file to which the analysis output must be '
            'written to. Default is output.csv'
        )
        self._parser.add_argument(
            '--szz-depth', default='3',
            help='Depth value to be passed into SZZUnleashed'
        )
        self._parser.add_argument(
            'repository', type=pathlib.Path,
            help='Absolute path to the local clone of the git repository containing '
            'the source code of the project being analyzed.'
        )
        self._parser.add_argument(
            'vulnerabilities', type=pathlib.Path,
            help='Absolute path to the local clone of the git repository containing '
            'the vulnerabilities in the project being analyzed curated by the '
            'Vulnerability History Project.'
        )

    def get_arguments(self):
        arguments = self._parser.parse_args()
        return arguments
