from dataclasses import dataclass, field
from typing import Optional

@dataclass
class TenantContext:
    tenant_id: str = "default"
    role: str = "analyst"
    owner_email: Optional[str] = None

    def get(self, key, default=None):
        return getattr(self, key, default)

def get_tenant():
    return TenantContext()
