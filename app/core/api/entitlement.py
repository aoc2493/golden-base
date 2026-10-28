# -*- coding: utf-8 -*-
"""权益校验路由：前端 checkRight 的统一入口（POST /entitlement/check）。

前端在结果页 / 各能力入口先调本接口判断「是否已解锁」，再决定走付费下单还是直接
读结果。校验逻辑全部复用 services.entitlement.check_feature（会员放行 / 否则查
feature+biz_key 有效权益），本路由只做参数归一与结果透传。

能力清单（feature 是否合法、sides 如何派生 biz_key）全部来自插件，core 零业务分支。
"""
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.auth import get_current_user
from app.core.api.common import success, error, ErrorCode
from app.core.database import get_db
from app.core.models import User
from app.core.services.entitlement import check_feature
from app.plugins import registry

router = APIRouter(prefix="/entitlement", tags=["权益"])


class EntitlementCheckRequest(BaseModel):
    feature: str
    biz_key: Optional[str] = None
    # 需要服务端派生 biz_key 的能力专用：上送原始 sides（如双人内容双方出生信息）
    sides: Optional[list] = None
    relation: Optional[str] = None


@router.post("/check")
async def entitlement_check(req: EntitlementCheckRequest,
                            user: User = Depends(get_current_user),
                            db: AsyncSession = Depends(get_db)):
    """功能解锁校验：返回 {allowed, vip, source, entitlements:[{order_id,...}]}。"""
    if req.feature not in registry.feature_names():
        return error(ErrorCode.PARAM_ERROR, f"不支持的功能: {req.feature}")
    entry, cap = registry.cap_by_code(req.feature)
    biz_key = req.biz_key
    if entry is not None and cap is not None and req.sides:
        # biz_key 派生委托给对应插件（服务端统一算法，前端无法伪造）
        derived = entry.service.derive_check_biz_key(cap, req.sides, req.relation)
        if derived:
            biz_key = derived
    result = await check_feature(db, user.id, req.feature, biz_key)
    return success(result)
