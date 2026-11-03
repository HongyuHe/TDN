"""Public records distinguish observed state, declarations, and unavailable data."""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Device(StrictModel):
    id: str
    worker: str
    container: str
    adapters: list[str]
    declared_role: str | None = None


class Network(StrictModel):
    id: str
    devices: list[Device]


class SavedExperiment(StrictModel):
    path: str
    parser: Literal["l2-filter-admission-v1", "pkcs11-token-binding-v1", "pkcs11-token-extra-v1", "pkcs11-token-boundary-v1", "key-interface-audit-v1", "os-provider-identity-v1", "guest-clock-use-v1", "mixed-protocol-v1", "mixed-packet-sizing-v1", "eap-correlation-v1", "eap-public-v1", "eap-mka-public-v1", "administration-observations-v1", "administration-lifecycle-v1", "cover-sender-v1", "native-component-audit-v1", "management-session-v1", "native-ipsec-correlation-v1", "native-packet-sizing-v1"]


class Settings(StrictModel):
    store: str
    lean_output: str | None = None
    networks: list[Network] = Field(default_factory=list)
    saved_snapshots: dict[str, str] = Field(default_factory=dict)
    saved_execution_supplements: dict[str, str] = Field(default_factory=dict)
    execution_epoch_union: list[str] = Field(default_factory=list)
    saved_experiments: dict[str, SavedExperiment] = Field(default_factory=dict)
    adapter_modules: list[str] = Field(default_factory=list)


class Observation(StrictModel):
    id: str
    device: str
    worker: str
    adapter: str
    capability: str
    argv: list[str]
    started: str
    finished: str
    exit_code: int | None
    status: Literal["observed", "failed", "unsupported", "unavailable"]
    path: str
    sha256: str
    stderr_path: str
    stderr_sha256: str
    parser_version: str
    records: list[dict[str, Any]] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)


class Manifest(StrictModel):
    schema_version: Literal[1] = 1
    id: str
    network: str
    started: str
    finished: str
    consistency: Literal["stable-during-recheck", "changed", "not-checked"]
    devices: list[Device]
    observations: list[Observation]
    source_kind: Literal["live", "saved"] = "live"
