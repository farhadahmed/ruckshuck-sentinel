from pydantic import BaseModel
from typing import Any, Dict, List

class RunResponse(BaseModel):
    rows: List[Dict[str, Any]]
