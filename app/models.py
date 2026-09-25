from enum import Enum

from pydantic import BaseModel, Field


class AssetKind(str, Enum):
    patent_disclosure = "专利交底书"
    technical_document = "工艺技术文档"
    source_media = "源代码介质"
    laboratory_record = "实验记录"
    design_drawing = "工程图纸"


class SecrecyLevel(str, Enum):
    internal = "内部"
    confidential = "秘密"
    restricted = "机密"
    top_secret = "绝密"


class DossierLabel(BaseModel):
    asset_kind: AssetKind
    secrecy_level: SecrecyLevel
    owner_department: str = Field(min_length=1, max_length=100)
    retention_until: str | None = None
    export_restriction: bool = False


class PatentMilestone(BaseModel):
    dossier_id: int = Field(gt=0)
    jurisdiction: str = Field(min_length=2, max_length=30)
    application_number: str = Field(min_length=3, max_length=80)
    milestone: str = Field(min_length=2, max_length=50)
    occurred_at: str


class AccessPurpose(BaseModel):
    requester_user_id: int = Field(gt=0)
    dossier_id: int = Field(gt=0)
    purpose: str = Field(min_length=4, max_length=500)
    expires_at: str
