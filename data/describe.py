from enum import Enum
from dataclasses import dataclass
import typing as tp


@dataclass
class Int:
    length: int


@dataclass
class String:
    length: int


@dataclass
class Struct:
    name: str


@dataclass
class Array:
    struct: Struct


@dataclass
class Enum:
    length: int
    name: str


@dataclass
class Char:
    pass


STRUCTS: tp.Dict[str, object] = {}
