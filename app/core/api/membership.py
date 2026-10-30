"""会员路由：状态查询（前端契约 data.membership）+ 套餐列表 + 完整会员规则（价格/天数/规则以后端为准）。"""
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.auth import get_current_user
from app.core.api.common import success
from app.config import settings
from app.core.database import get_db
from app.core.models import User, Product
from app.core.services.config_helper import get_config
from app.core.services.membership import get_member_status, days_for_level, level_of_sku, build_membership_rules, MEMBERSHIP_RULE_LABELS

router = APIRouter(prefix="/membership", tags=["会员"])


@router.get("/status")
async def membership_status(user: User = Depends(get_current_user),
                            db: AsyncSession = Depends(get_db)):
    """查询当前会员状态（档位/到期时间/剩余额度）。

    前端契约要求 data.membership 包裹状态对象
    （page-logic.js 三处均以 ms.membership.level / is_vip / in_grace 读取）。
    必须用 data.membership 包裹状态字典，否则会员中心会误判「状态获取失败」
    并把购买入口整段隐藏。

    with_usage=True：额度卡要展示 period_used（本周期已用），而 get_member_status
    默认不统计该项（见其 docstring）。这是唯一需要该统计的调用方。
    """
    status = await get_member_status(db, user.id, with_usage=True)
    return success({"membership": status})


@router.get("/plans")
async def membership_plans(user: User = Depends(get_current_user),
                           db: AsyncSession = Depends(get_db)):
    """会员套餐列表（会员中心购买页）。价格一律取自商品表（禁止前端定价），
    天数由档位规则给出（月30/年365/终身None=永久）。

    前端 Api.memberPlans 调用本接口，原缺失路由让套餐区抛异常、
    fail-closed 隐藏全部购买入口——会员中心整页瘫痪。
    """
    rows = (await db.execute(
        select(Product).where(Product.product_type == "membership",
                              Product.enabled == 1)
        .order_by(Product.sort_order.asc(), Product.id.asc()))).scalars().all()
    return success({"list": [{
        "sku_code": p.sku_code,
        "name": p.name,
        "description": p.description,
        "price": float(p.price),
        # days_for_level 收的是「档位」(month/year/lifetime)，不是商品 sku_code；
        # 月/年档必须先用 level_of_sku 归一化，终身档为 None（无到期日）。
        "days": days_for_level(level_of_sku(p.sku_code)),   # vip_lifetime -> None
    } for p in rows]})


@router.get("/rules")
async def membership_rules(user: User = Depends(get_current_user),
                           db: AsyncSession = Depends(get_db)):
    """会员规则完整文案（《会员体系规则 V1.3》）：三档/固定天数/宽限期/额度池/
    全价升级顺延/续费顺延/连续会员/会员期屏蔽单次购买/退款。

    之前会员规则无任何接口（只有 /status 与 /plans），用户无处查看完整规则。
    文案以 settings 为权威来源构建（数值与实际生效规则一致），system_configs.membership_rules
    可按键覆盖（运营自定义）。sections 为按固定顺序的展示数组，前端直接渲染。
    """
    rules = await build_membership_rules(db)
    version = await get_config(db, "membership_rule_version", settings.MEMBERSHIP_RULE_VERSION)
    sections = [{"key": k, "label": lb, "value": rules[k]}
                for k, lb in MEMBERSHIP_RULE_LABELS if rules.get(k)]
    return success({"version": version, "rules": rules, "sections": sections})
