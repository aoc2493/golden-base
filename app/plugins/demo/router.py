# -*- coding: utf-8 -*-
"""Demo 业务接口：支付前 403，支付后可调用。"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api.common import ErrorCode, error, success
from app.core.auth import get_current_user
from app.core.database import get_db
from app.core.models import User
from app.core.services.entitlement import check_feature
from app.plugins.demo.manifest import DEMO_FEATURE
from app.plugins.demo.service import echo_biz_key

router = APIRouter(prefix="/demo", tags=["Demo"])


class EchoRequest(BaseModel):
    text: str


@router.post("/echo")
async def echo(req: EchoRequest, user: User = Depends(get_current_user),
               db: AsyncSession = Depends(get_db)):
    text = (req.text or "").strip()
    if not text:
        return error(ErrorCode.PARAM_ERROR, "请输入要回显的文本")
    checked = await check_feature(db, user.id, DEMO_FEATURE, echo_biz_key(text))
    if not checked.get("allowed"):
        return error(ErrorCode.NO_PERMISSION, "该内容尚未购买")
    return success({"text": text, "length": len(text)})
