"""Telemetry and search result models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class TelemetryEvent(BaseModel):
    """A single ECS-normalised telemetry event."""

    timestamp: datetime = Field(alias="@timestamp", default_factory=datetime.utcnow)
    event_action: str = Field(default="", alias="event.action")
    event_category: list[str] = Field(default_factory=list, alias="event.category")
    event_kind: str = Field(default="event", alias="event.kind")

    # Process fields
    process_name: str = Field(default="", alias="process.name")
    process_executable: str = Field(default="", alias="process.executable")
    process_args: list[str] = Field(default_factory=list, alias="process.args")
    process_pid: int | None = Field(default=None, alias="process.pid")
    process_command_line: str = Field(default="", alias="process.command_line")
    process_parent_name: str = Field(default="", alias="process.parent.name")

    # Host fields
    host_name: str = Field(default="", alias="host.name")
    host_os_type: str = Field(default="linux", alias="host.os.type")

    # Network fields
    source_ip: str = Field(default="", alias="source.ip")
    destination_ip: str = Field(default="", alias="destination.ip")
    destination_port: int | None = Field(default=None, alias="destination.port")

    # User fields
    user_name: str = Field(default="", alias="user.name")

    # File fields
    file_path: str = Field(default="", alias="file.path")
    file_name: str = Field(default="", alias="file.name")

    # Additional raw fields
    extra: dict = Field(default_factory=dict, description="Any un-mapped ECS fields")

    model_config = {"populate_by_name": True}

    def to_es_doc(self) -> dict:
        """Serialise to a flat Elasticsearch document (dotted-key format)."""
        doc: dict = {"@timestamp": self.timestamp.isoformat()}
        field_map = {
            "event.action": self.event_action,
            "event.category": self.event_category,
            "event.kind": self.event_kind,
            "process.name": self.process_name,
            "process.executable": self.process_executable,
            "process.args": self.process_args,
            "process.pid": self.process_pid,
            "process.command_line": self.process_command_line,
            "process.parent.name": self.process_parent_name,
            "host.name": self.host_name,
            "host.os.type": self.host_os_type,
            "source.ip": self.source_ip,
            "destination.ip": self.destination_ip,
            "destination.port": self.destination_port,
            "user.name": self.user_name,
            "file.path": self.file_path,
            "file.name": self.file_name,
        }
        for key, val in field_map.items():
            if val and val != "" and val != [] and val is not None:
                doc[key] = val
        doc.update(self.extra)
        return doc


class SearchResult(BaseModel):
    """Result from executing a rule query against a dataset."""

    total_hits: int = Field(ge=0, description="Number of matching documents")
    total_docs: int = Field(ge=0, description="Total documents in the searched scope")
    took_ms: int = Field(default=0, ge=0, description="Query execution time in ms")
    sample_hits: list[dict] = Field(
        default_factory=list, description="Sample matching documents (max 20)"
    )
    query_used: dict = Field(default_factory=dict, description="The actual query executed")
    index_pattern: str = Field(default="", description="Index pattern queried")
    time_range_start: datetime | None = Field(default=None)
    time_range_end: datetime | None = Field(default=None)

    @property
    def hit_rate(self) -> float:
        """Proportion of matching documents."""
        if self.total_docs == 0:
            return 0.0
        return self.total_hits / self.total_docs
