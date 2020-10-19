# archeogit-vs-szz

## Usage

```
$ python main.py --help
usage: main.py [-h] [--config-file CONFIG_FILE] repository vulnerabilities

Compare performance of archeogit and SZZ Unleashed.

positional arguments:
  repository            Path to the local clone of the git repository
                        containing the source code of the project being
                        analyzed.
  vulnerabilities       Path to the local clone of the git repository
                        containing the vulnerabilities in the project being
                        analyzed curated by the Vulnerability History Project.

optional arguments:
  -h, --help            show this help message and exit
  --config-file CONFIG_FILE
                        Path to the configuration file. Default is config.yml.
```

## Environment

The application has been tested on an environment identified below.

 * Ubuntu 18.04.5 LTS
 * Python 3.7.2
 * virtualenv 16.4.0
 * pip 20.2.4
