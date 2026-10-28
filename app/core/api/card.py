"""用户端卡券接口：输码兑换 + 我的卡券

接入要点：
1) 鉴权直接复用 H5 的 app.auth.get_current_user（JWT 验签 + Redis 黑名单 + 用户存在性校验）。
   独立版是「直接读 X-User-Id 请求头」，等于没有鉴权——任何人填 X-User-Id: 1 就能把卡
   兑到别人账户、翻别人卡券。该模式已彻底移除。

2) 本模块**不提供** /feature/check 与 /feature/consume：
   · check 与 H5 已有的 /api/entitlement/* 功能重复；
   · consume（核销）与 H5 的权益语义根本冲突——H5 的 check_feature 只认
     status='available'，一旦核销，用户再看自己已生成的报告都会被拒；
     H5 的「一次性」是靠 biz_key 绑定 + 订单复用实现的，不需要核销。
   消耗逻辑一律沿用现有链路（插件的 ensure-report / entitlement）。

3) 限流为「按用户 + 按来源 IP」双维度。独立版只按 user_id 限流，而 user_id 当时可
   随意伪造，攻击者每换一个 header 就重置限流桶，卡密爆破实际零成本。
"""
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
        # 失败同样必须留痕：渠道一批码被重复投放、卡密被翻录后按字典序撞库、
        # 过期卡未及时下架，都只能从失败率曲线看出来。此前只有成功日志，
        # 一次大规模撞库在系统里是完全不可见的。日志只记脱敏码，不落明文凭据。
        logger.warning(
            f"卡券兑换失败 user={user.id} ip={get_client_ip(request)} "
            f"code={card_svc.mask_code(req.code)} reason={e.msg}")
        # persist=True：本次失败同时需要保留「过期卡自动作废」的状态变更，
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
