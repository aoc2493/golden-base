# Contributing

欢迎提交 Issue 与 Pull Request。

## 开发流程

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

提交前请确认：

- `pytest` 全绿
- 没有提交 `.env`、证书、密钥或本地数据库
- 新增业务逻辑放在 `app/plugins/<name>/`，不要往 `app/core/` 里加业务词
- 涉及支付 / 权益 / 退款的改动，补一条可复现的测试

## 提交信息

使用 Conventional Commits 风格的简短标题，例如：

```
feat(plugin): add quota check to demo capability
fix(payment): reject callback with mismatched amount
docs: clarify PAYMENT_MOCK scope
```

## 代码约定

- core 零业务词：能力码、SKU、价格、文案不写死在 `app/core/`
- 价格只信后端：前端只传「买什么」，不传金额
- 不做破坏式改动时优先保持接口与表结构兼容
- 注释只解释「为什么」，不复述代码在做什么

## 安全

见 [SECURITY.md](SECURITY.md)。安全问题请走私密报告渠道。
