import hashlib
import json
import os
from pathlib import Path


def configuration():
    location=Path(os.environ.get("TDN_INPUT_MANIFEST","inputs/source_paths.json"))
    result=json.loads(location.read_text())
    if result.get("schema_version")!="csfc-construction-inputs/v1":
        raise ValueError("unsupported construction input manifest")
    return result


def source_path(name):
    value=Path(configuration()["paths"][name])
    if value.is_absolute() or ".." in value.parts:
        raise ValueError("source path must be workspace-relative")
    return value


def verified_source(name):
    config=configuration()
    path=source_path(name)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=config["hashes"][name]:
        raise ValueError("source declaration hash mismatch")
    return path


def output_path(name=""):
    base=Path(os.environ.get("TDN_OUTPUT_DIR","outputs"))
    if base.is_absolute() or ".." in base.parts:
        raise ValueError("output directory must be workspace-relative")
    return base/name


def source_collection(name):
    config=configuration()
    mapping=config.get("collections",{}).get(name)
    if mapping is None:
        return [p.parent for p in sorted(source_path(name).glob("*/manifest.json"))]
    if not isinstance(mapping,dict) or not mapping:
        raise ValueError("source collection must be a nonempty ID/path mapping")
    paths=[]
    for identity,value in sorted(mapping.items()):
        path=Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("collection path must be workspace-relative")
        if not (path/"manifest.json").is_file():
            raise ValueError("source collection manifest missing: "+identity)
        paths.append(path)
    if len(paths)!=len(set(paths)):
        raise ValueError("duplicate source collection bundle")
    return paths
