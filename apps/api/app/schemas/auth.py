import uuid
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr

# Auth Schemas
class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str
    company_name: Optional[str] = None

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    first_name: str
    last_name: str
    tenant_id: uuid.UUID
    mfa_enabled: bool
    roles: List[str] = []

class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str

class RefreshRequest(BaseModel):
    refresh_token: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class MFASetupResponse(BaseModel):
    secret: str
    uri: str

class MFAVerifyRequest(BaseModel):
    code: str

class LoginMfaResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str

class LoginMfaRequest(BaseModel):
    mfa_token: str
    code: str
