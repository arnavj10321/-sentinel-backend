from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    type: str
    source: Optional[str] = None
    message: Optional[str] = None
    severity: str
    created_at: datetime
