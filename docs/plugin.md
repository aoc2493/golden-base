# 编写业务插件

底座只做两件事：**卖能力**、**核销权益**。业务差异全部收敛在
`app/plugins/<name>/` 一个目录里。启动时 `registry.discover()` 自动扫描，
`main.py` 自动把插件路由挂到 `/api`，core 与入口文件零改动。

> **信任边界**：插件与 core 同进程同权限，能拿数据库会话、读 `settings` 里的支付密钥，
> 也能注册任意路由——底座不提供沙箱。把 `app/plugins/` 当作可信代码对待：只安装
> 经过审计的插件，第三方插件上线前必须代码评审。详见 `SECURITY.md`。

## 目录约定

```
app/plugins/<name>/
├─ manifest.py   # 必须：MANIFEST: PluginManifest
├─ service.py    # 必须：service 对象，实现钩子
├─ router.py     # 可选：暴露 router（APIRouter）
└─ api/*.py      # 可选：每个模块暴露一个 router
```

`MANIFEST.name` 必须与目录名一致，否则启动报错。

## 1. 声明能力

```python
# manifest.py
from app.core.plugin_contract import (
    BILLING_ORDER, DELIVERY_NONE, Capability, PluginManifest,
)

MANIFEST = PluginManifest(
    name="your_biz",
    display_name="你的业务",
    capabilities=[
        Capability(
            code="your.feature",      # 能力码，全局唯一，权益按它记账
            sku="your_sku",           # 单次 SKU，全局唯一
            name="展示名",
            billing_model=BILLING_ORDER,
            delivery=DELIVERY_NONE,   # report / none
            single_price_cents=100,   # 1.00 元
            member_included=True,     # 会员是否覆盖
            member_view_sku="your_view_sku",  # 会员覆盖时必填
        ),
    ],
)
```

关键约束（启动时校验）：

| 场景 | 要求 |
|---|---|
| 付费能力 | `single_price_cents > 0` |
| 会员覆盖 | 必须提供 `member_view_sku` |
| 有上游成本 | 必须提供 `daily_budget_cents` |
| 独立计费（会员不覆盖） | `independent_coupon=True` 且 `member_included=False`，且只支持 `BILLING_ORDER` |

## 2. 实现钩子

```python
# service.py
from app.core.plugin_contract import OrderPrep, PaidResult

class YourService:
    async def prepare_order(self, cap, raw, user, db) -> OrderPrep:
        # 校验入参、生成业务快照与 biz_key；抛 PluginError 可返回统一错误信封
        return OrderPrep(biz_data={"...": "..."}, input_snapshot={...}, biz_key="...")

    async def on_paid(self, cap, order, db) -> PaidResult:
        # 只返回「业务事实」；发权益/计佣由 core 完成
        return PaidResult(biz_key="...")

    def on_refund(self, cap, order, db):
        # 退款时回收业务数据；权益撤销由 core 统一处理
        return None

    async def seed_data(self, db) -> None:
        # 可选：把自己可售商品写入 products 表（价源仍以 manifest 为准）
        ...

service = YourService()
```

可用钩子一览：

| 钩子 | 时机 | 说明 |
|---|---|---|
| `prepare_order` | 下单 | 产出业务快照 / biz_key |
| `on_paid` | 支付成功 | 返回 biz_key、是否需要后台生成 |
| `on_refund` | 退款成功 | 回收业务数据 |
| `seed_data` | 启动 | 幂等写入商品行 |
| `generation_task` | 报告型能力 | 返回后台生成协程 |
| `derive_check_biz_key` | 权益校验 | 服务端从 sides 派生 biz_key |
| `on_user_erase` | 注销 | 清理插件专属数据 |
| `favorite_types` / `describe_favorite` / `favorite_alive` | 收藏 | 插件自有收藏类型 |
| `admin_user_dump` | 后台用户详情 | 贡献插件侧数据片段 |
| `vip_benefits` | 会员中心 | 会员权益文案 |

**边界铁律**：插件不得直接写权益 / 订单 / 会员 / 卡券表，不得直接收款或结算佣金。

## 3. 暴露业务接口

```python
# router.py
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.api.common import ErrorCode, error, success
from app.core.auth import get_current_user
from app.core.database import get_db
from app.core.models import User
from app.core.services.entitlement import check_feature

router = APIRouter(prefix="/your-biz", tags=["Your Biz"])

@router.post("/run")
async def run(payload: dict, user: User = Depends(get_current_user),
              db: AsyncSession = Depends(get_db)):
    checked = await check_feature(db, user.id, "your.feature", payload.get("biz_key"))
    if not checked["allowed"]:
        return error(ErrorCode.NO_PERMISSION, "该内容尚未购买")
    return success({...})
```

路由最终地址是 `/api` + `router.prefix` + 路径。

## 4. 跑通验证

```bash
pytest                       # 全量回归
uvicorn app.main:app --reload  # 非生产环境带 /docs
```

参考实现：`app/plugins/demo/`（含独立计费、biz_key 派生、商品种子、越权保护的测试）。
