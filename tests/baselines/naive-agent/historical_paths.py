"""Resolve the original names in immutable experiment manifests after the directory move."""
from pathlib import Path

BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[2]


def historical_path(name):
    path=Path(name)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('Expected a repository-relative recorded path')
    prefix=('tests','baselines','agent')
    if path.parts[:3]!=prefix:
        return ROOT/path
    rest=Path(*path.parts[3:])
    if rest.parts[:1] in (('profiles',),('requirements.json',)):
        return BASE/'legacy'/rest
    return BASE/rest
