from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.models import User, Order, Report, Favorite
from app.core.auth import get_current_user
from app.core.api.common import success, error, ErrorCode
from app.plugins import registry

router = APIRouter(prefix="/favorite", tags=["收藏"])

# 收藏上限：防无限写入的存储放大入口
FAVORITE_MAX_PER_USER = 200


class FavoriteAddRequest(BaseModel):
    item_type: str = Field(..., description="收藏类型：report（core）或插件声明的业务类型")
    item_id: int = Field(..., gt=0)


def _fmt_dt(dt):
    return dt.strftime("%Y-%m-%d %H:%M") if dt else None


@router.get("/list")
async def favorite_list(db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_user)):
    """收藏列表。source_alive 标记源是否仍可见：源被软删后收藏保留，前端据此打「源已删除」标签。
    业务类型（如 archive）的判活经插件钩子；core 自有 report 类型由 core 查 Report。"""
    rows = (await db.execute(select(Favorite).where(Favorite.user_id == user.id)
                             .order_by(Favorite.id.desc()))).scalars().all()

    # 按 item_type 分组
    grouped: dict[str, list[int]] = {}
    for r in rows:
        grouped.setdefault(r.item_type, []).append(r.item_id)

    alive: dict[str, set] = {}
    for itype, ids in grouped.items():
        if itype == "report":
            rep_rows = (await db.execute(select(Report.order_id, Report.deleted_at)
                                         .where(Report.order_id.in_(ids)))).all()
            alive[itype] = {oid for oid, del_at in rep_rows if del_at is None}
        else:
            provider = await registry.favorite_provider(itype)
            if provider is not None:
                alive[itype] = await provider.service.favorite_alive(itype, ids, db)
            else:
                alive[itype] = set()

    items = []
    for r in rows:
        items.append({
            "id": r.id, "item_type": r.item_type, "item_id": r.item_id,
            "title": r.title, "sub": r.sub, "payload": r.payload,
            "source_alive": r.item_id in alive.get(r.item_type, set()),
            "created_at": _fmt_dt(r.created_at),
        })
    return success({"list": items})


@router.post("")
async def favorite_add(req: FavoriteAddRequest,
                       db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    """收藏。快照一律服务端取（前端传什么信什么等于开放伪造展示内容的入口）；重复收藏幂等。"""
    exist = (await db.execute(select(Favorite).where(
        Favorite.user_id == user.id, Favorite.item_type == req.item_type,
        Favorite.item_id == req.item_id))).scalar_one_or_none()
    if exist:
        return success({"id": exist.id}, msg="已在收藏中")
    total = (await db.execute(select(Favorite.id).where(
        Favorite.user_id == user.id))).all()
    if len(total) >= FAVORITE_MAX_PER_USER:
        return error(ErrorCode.PARAM_ERROR, f"收藏数量已达上限（{FAVORITE_MAX_PER_USER}条）")

    if req.item_type == "report":
        row = (await db.execute(select(Order, Report).join(
            Report, Report.order_id == Order.id).where(
            Order.id == req.item_id, Order.user_id == user.id,
            Order.status == "completed", Report.deleted_at.is_(None)))).first()
        if not row:
            return error(ErrorCode.PARAM_ERROR, "报告不存在")
        order, _report = row
        title = (order.product_name or "解读报告")[:100]
        sub = _fmt_dt(order.created_at) or ""
        payload = None
    else:
        provider = await registry.favorite_provider(req.item_type)
        if provider is None:
            return error(ErrorCode.PARAM_ERROR, "不支持的收藏类型")
        snap = await provider.service.describe_favorite(
            req.item_type, req.item_id, user, db)
        if not snap:
            return error(ErrorCode.PARAM_ERROR, "收藏对象不存在")
        title, sub, payload = snap

    fav = Favorite(user_id=user.id, item_type=req.item_type, item_id=req.item_id,
                   title=title, sub=sub, payload=payload)
    db.add(fav)
    await db.flush()
    return success({"id": fav.id}, msg="已收藏")


@router.delete("/{favorite_id}")
async def favorite_delete(favorite_id: int,
                          db: AsyncSession = Depends(get_db),
                          user: User = Depends(get_current_user)):
    fav = (await db.execute(select(Favorite).where(
        Favorite.id == favorite_id, Favorite.user_id == user.id))).scalar_one_or_none()
    if not fav:
        return error(ErrorCode.PARAM_ERROR, "收藏不存在")
    await db.delete(fav)
    await db.flush()
    return success(msg="已取消收藏")
