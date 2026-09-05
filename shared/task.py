from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Task:
    task_id: str
    description: str
    payload: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    status: str = "created"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
