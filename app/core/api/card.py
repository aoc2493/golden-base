"""用户端卡券兑换与查询接口。"""
import logging

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api.common import ErrorCode, error, get_client_ip, redis_rate_limit, success
from app.core.auth import get_current_user, redis_client
from app.core.database import get_db
from app.core.services import card as card_svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/card", tags=["卡券"])

# 兑换限流：单用户 5 次/分（防同账号爆破卡密），单 IP 30 次/分（防换号绕过）
_REDEEM_LIMIT_USER = 5
_REDEEM_LIMIT_IP = 30


class CardRedeemRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=32, description="卡券码")


@router.post("/redeem")
async def card_redeem(request: Request,
                      req: CardRedeemRequest,
                      user=Depends(get_current_user),
                      db: AsyncSession = Depends(get_db)):
    """输码兑换：一码一用，行锁防并发双花。"""
    if not await redis_rate_limit(redis_client, f"card:redeem:u:{user.id}",
                                  _REDEEM_LIMIT_USER, 60):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")
    if not await redis_rate_limit(redis_client, f"card:redeem:ip:{get_client_ip(request)}",
                                  _REDEEM_LIMIT_IP, 60):
        return error(ErrorCode.RATE_LIMIT, "操作过于频繁，请稍后再试")

    try:
        result = await card_svc.redeem(db, req.code, user.id)
        await db.commit()
    except card_svc.CardRedeemError as e:
        # 失败同样必须留痕：渠道重复投放、卡密撞库、过期卡未下架都需要通过
        # 失败率曲线观察。日志只记脱敏码，不落明文凭据。
        logger.warning(
            f"卡券兑换失败 user={user.id} ip={get_client_ip(request)} "
            f"code={card_svc.mask_code(req.code)} reason={e.msg}")
        # persist=True：该次失败同时需要保留「过期卡自动作废」的状态变更，
        # 必须 commit；rollback 会把作废回滚掉，过期卡继续被导出到渠道售卖。
        if e.persist:
            await db.commit()
        else:
            await db.rollback()
        return error(ErrorCode.PARAM_ERROR, e.msg)
    except Exception as e:
        await db.rollback()
        logger.error(f"卡券兑换异常 user={user.id}: {e}", exc_info=True)
        return error(ErrorCode.PARAM_ERROR, "兑换失败，请稍后重试或联系客服")

    msg = f"兑换成功：{result['name']}已到账"
    if result.get("tip"):
        msg = f"{msg}。{result['tip']}"
    return success(result, msg)


@router.get("/mine")
async def card_mine(page: int = Query(1, ge=1, description="页码，从 1 开始"),
                    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
                    user=Depends(get_current_user),
                    db: AsyncSession = Depends(get_db)):
    """我的卡券（已兑换记录，卡密脱敏）。

    分页上限 100：公开接口不接受调用方指定任意大的 page_size，
    否则一个 page_size=100000 的请求就能把整表拉出来做遍历。
    """
    data = await card_svc.my_cards(db, user.id, page=page, page_size=page_size)
    return success(data)
