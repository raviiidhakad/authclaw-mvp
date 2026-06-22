import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, EmailStr

class UserCreateAdmin(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    role_name: Optional[str] = "viewer"

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = None

class RoleAssign(BaseModel):
    roles: List[str]

class UserResponseWithRoles(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    first_name: str
    last_name: str
    tenant_id: uuid.UUID
    is_active: bool
    last_login_at: Optional[datetime]
    created_at: datetime
    roles: List[str] = []
    mfa_enabled: bool = False
