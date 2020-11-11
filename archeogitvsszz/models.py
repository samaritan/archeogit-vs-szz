import dataclasses
import typing


@dataclasses.dataclass
class Vulnerability:
    __slots__ = ['cve', 'fixes', 'contributors']

    cve: str
    fixes: typing.Set[str]
    contributors: typing.Set[str]
