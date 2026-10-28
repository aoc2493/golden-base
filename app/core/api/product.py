"""商品（SKU）接口：前端展示价格一律以此为准，禁止前端定价"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import get_db
from app.core.models import Product, User
from app.core.auth import get_current_user
from app.core.api.common import success

router = APIRouter(prefix="/product", tags=["商品"])


def _product_dict(p: Product) -> dict:
    return {
        "id": p.id,
        "sku_code": p.sku_code,
        "product_type": p.product_type,
        "feature": p.feature,
        "name": p.name,
        "description": p.description,
        "price": float(p.price),
        "refund_rule": p.refund_rule,
        "sort_order": p.sort_order,
    }


@router.get("/list")
async def product_list(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """全部在售商品（会员套餐 + 单次 + 按天工具），按 sort_order 排序"""
    result = await db.execute(
        select(Product).where(
            Product.enabled == 1,
            Product.product_type != "timepass",
        ).order_by(Product.sort_order.asc(), Product.id.asc())
    )
    items = [_product_dict(p) for p in result.scalars().all()]
    return success({"list": items})
