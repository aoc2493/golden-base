"""分销合规留痕与敏感词检测。"""
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import ComplianceConsent, SensitiveWord, Distributor, User

logger = logging.getLogger(__name__)

DOC_COMMITMENT = "promoter_commitment"     # 合规推广承诺书
DOC_PAYMENT_DISCLAIMER = "payment_disclaimer"  # 支付前免责勾选
DOC_RULE_CHANGE = "rule_change"            # 规则重大不利变更确认


# ==================== 第十二/五十六/五条：合规留痕 ====================
async def record_consent(db: AsyncSession, user: User, doc_type: str, doc_version: Optional[str] = None,
                         agreed: bool = True, order_id: Optional[int] = None, ip: Optional[str] = None,
                         user_agent: Optional[str] = None, dist: Optional[Distributor] = None):
    """记录一次合规勾选/签署留痕（第五十九条：文本版本号、时间戳、IP/设备，保存≥3年）。

    agreed=0 的行表示【撤回同意】（个保法第十五条），由 services.consent.withdraw 追加。
    撤回一律是「追加一行」而不是删掉当前的同意行：留痕是法定义务，删行等于销毁证据；
    当前状态以「最新一行」为准，因此下面的 has_signed 必须按最新行判。"""
    rec = ComplianceConsent(user_id=user.id, distributor_id=(dist.id if dist else None),
                            doc_type=doc_type, doc_version=doc_version, agreed=1 if agreed else 0,
                            order_id=order_id, ip=ip, user_agent=(user_agent or "")[:255])
    db.add(rec)
    # 承诺书签署时点同步到推广员档案
    if doc_type == DOC_COMMITMENT and agreed and dist:
        await db.execute(update(Distributor).where(Distributor.id == dist.id).values(
            consent_signed_at=datetime.now()).execution_options(synchronize_session="fetch"))
    await db.flush()
    return rec


async def has_signed(db: AsyncSession, user_id: int, doc_type: str) -> bool:
    """是否【当前】处于已签署/已同意状态（取最新一行且 agreed=1）。

    取最新一行，而不是「有没有 agreed=1 的行」。一旦支持撤回（services.consent 会
    追加 agreed=0 的行），旧口径会把已撤回的人继续当成已同意——用户明明撤回了，系统
    仍继续处理他的个人信息，且从界面上完全看不出来，这是第十五条的直接违反。
    排序用 id 而不是 agreed_at：同一秒内可能有多行（先撤回再重新同意），时间戳分不出
    先后，自增 id 能。

    调用方：order.create 在 ENFORCE_PAYMENT_DISCLAIMER=true 时用它校验
    DOC_PAYMENT_DISCLAIMER（第五十六条第3款 支付前免责勾选），未签署者挡在下单前。
    隐私同意走 services/consent.py 的 ensure_privacy_consent（对从未留痕的存量用户
    fail-open），文书版本比对走 latest_agreed_version，二者语义更专用，不共用本函数。
    仍没有服务端准入判定的是 DOC_COMMITMENT（第十二条 合规推广承诺书）：
    consent_signed_at 只写不读，接入应对称调用本函数。"""
    rec = (await db.execute(select(ComplianceConsent).where(
        ComplianceConsent.user_id == user_id, ComplianceConsent.doc_type == doc_type)
        .order_by(ComplianceConsent.id.desc()).limit(1))).scalar_one_or_none()
    return rec is not None and int(rec.agreed or 0) == 1


# ==================== 第五十七/五十八条：敏感词检测 ====================
async def check_sensitive(db: AsyncSession, text: str) -> dict:
    """检测文本命中敏感词。返回 {blocked, warned, hits:[{word,level,category}]}。
    一级拦截词（level=1）→ blocked=True（禁止并告警，对应第六十条中度）；
    二级预警词（level=2）→ warned=True（仅警告、放行，对应第六十条轻度）。
    注意：严重度与 level 数值相反（1 比 2 严重），故不用 max_level，改用 blocked/warned 两个布尔位直连规则两级处置。

    词库维护由 admin.py 调用；命中侧挂在 core 的用户 UGC 入口：
      · user.py update_user_info（改昵称）、feedback.py submit_feedback（反馈内容）——
        blocked 拒绝（ErrorCode.CONTENT_VIOLATION）、warned 放行 + 文字提示；
      · auth.py sync_wechat_profile（微信昵称）——命中任一级别即跳过昵称落库 + 告警，
        不阻断同步（堵住「微信改违规昵称→同步」的绕过路径）。
    垂直业务若有自己的推广文案/发布入口，应在其插件内同样调用本函数。"""
    text = text or ""
    if not text.strip():
        return {"blocked": False, "warned": False, "hits": []}
    words = (await db.execute(select(SensitiveWord).where(SensitiveWord.enabled == 1))).scalars().all()
    hits = []
    low = text.lower()
    for w in words:
        token = (w.word or "").strip()
        if token and token.lower() in low:
            hits.append({"word": token, "level": int(w.level or 2), "category": w.category})
    blocked = any(h["level"] == 1 for h in hits)
    warned = any(h["level"] == 2 for h in hits)
    if blocked:
        logger.warning(f"[敏感词·一级拦截] 命中 {[h['word'] for h in hits if h['level']==1]}")
    return {"blocked": blocked, "warned": warned, "hits": hits}


async def list_sensitive_words(db: AsyncSession, enabled_only: bool = True) -> list:
    stmt = select(SensitiveWord)
    if enabled_only:
        stmt = stmt.where(SensitiveWord.enabled == 1)
    rows = (await db.execute(stmt.order_by(SensitiveWord.level.asc(), SensitiveWord.id.desc()))).scalars().all()
    return [{"id": w.id, "word": w.word, "level": int(w.level or 2),
             "category": w.category, "enabled": int(w.enabled or 0)} for w in rows]


async def upsert_sensitive_word(db: AsyncSession, word: str, level: int = 2,
                                category: Optional[str] = None, enabled: int = 1):
    """新增或更新敏感词（word 唯一）。level 1=一级拦截/2=二级预警。"""
    word = (word or "").strip()
    if not word:
        return None
    row = (await db.execute(select(SensitiveWord).where(SensitiveWord.word == word))).scalar_one_or_none()
    if row:
        await db.execute(update(SensitiveWord).where(SensitiveWord.id == row.id).values(
            level=level, category=category, enabled=enabled))
        await db.flush()
        return row
    row = SensitiveWord(word=word, level=level, category=category, enabled=enabled)
    db.add(row)
    await db.flush()
    return row
