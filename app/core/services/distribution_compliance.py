"""
分销合规钩子服务 V1.3
覆盖规则：
- 第七条：合规入门考试（满分100、80及格、不限次数直至通过；通过置 exam_passed=1）
- 第十二条：《合规推广承诺书》签署留痕（promoter_commitment）
- 第五十六条第3款：用户支付前免责主动勾选留痕（payment_disclaimer）
- 第五条第2款：规则重大不利变更单独勾选确认（rule_change）
- 第五十七/五十八条：敏感词库检测（一级拦截词禁止并告警 / 二级预警词首次警告）
- 第五十条：外部推广账号报备与审核
- 第五十八条第3款：用户举报工单（24h 内响应、核查、反馈）
所有留痕记录保存不少于 3 年（第五十九条），config.DIST_CONSENT_RETENTION_YEARS。
本模块只负责「写留痕 + 读当前状态」；同意/撤回的业务语义（哪些项可撤回、撤回后停什么）
在 services/consent.py，两者共用 compliance_consents 表。
"""
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import (ExamQuestion, ExamRecord, ComplianceConsent, SensitiveWord,
                        ExternalAccount, ReportTicket, Distributor, User)
from app.config import settings

logger = logging.getLogger(__name__)

DOC_COMMITMENT = "promoter_commitment"     # 合规推广承诺书
DOC_PAYMENT_DISCLAIMER = "payment_disclaimer"  # 支付前免责勾选
DOC_RULE_CHANGE = "rule_change"            # 规则重大不利变更确认


# ==================== 第七条：合规入门考试 ====================
def _answer_correct(q: ExamQuestion, given: str) -> bool:
    """判分：多选按集合相等，单选/判断按归一化字符串相等。"""
    correct = (q.answer or "").strip()
    given = (given or "").strip()
    if not given or not correct:
        return False
    if (q.qtype or "single") == "multiple":
        gset = {x.strip().upper() for x in given.replace("，", ",").split(",") if x.strip()}
        cset = {x.strip().upper() for x in correct.replace("，", ",").split(",") if x.strip()}
        return gset == cset
    return given.upper() == correct.upper()


async def get_exam_paper(db: AsyncSession) -> dict:
    """【未接线·无端点使用本函数】取考试试卷（不含正确答案）：供推广中心答题页展示。

    待接线说明（本次死代码清理仅标记、未改动行为）：
    第七条的合规入门考试用户侧完全没有入口：本函数与同段的 submit_exam、
    get_exam_status 三者全库零调用点，配套的 schemas.ExamSubmitRequest 也没有任何
    端点使用。当前后果是 distributors.exam_passed 恒为 0，而后台 admin.py 的用户
    详情仍在展示该字段（永远 False），main.py 启动时仍会往空表种 10 道考题。
    接线时需在 api/distribution.py 增加「取卷 / 交卷 / 查状态」三个端点，并把
    exam_passed 作为成为推广员的准入校验。"""
    qs = (await db.execute(select(ExamQuestion).where(ExamQuestion.enabled == 1)
                           .order_by(ExamQuestion.sort_order.asc(), ExamQuestion.id.asc()))).scalars().all()
    items = [{"id": q.id, "category": q.category, "content": q.content,
              "options": q.options, "qtype": q.qtype or "single", "score": int(q.score or 0)}
             for q in qs]
    return {"full_score": settings.DIST_EXAM_FULL_SCORE,
            "pass_score": settings.DIST_EXAM_PASS_SCORE,
            "total": len(items), "questions": items}


async def submit_exam(db: AsyncSession, user: User, dist: Optional[Distributor], answers: dict) -> dict:
    """【未接线·无端点使用本函数】第七条：提交作答并判分记录。满分100、80及格；通过则置 exam_passed=1（不限次数直至通过）。
    answers: {question_id: "A" 或 "A,B"(多选)}，键可为 str 或 int。

    待接线说明见同段 get_exam_paper：考试功能用户侧整体未接线，仅标记、未改动行为。"""
    qs = (await db.execute(select(ExamQuestion).where(ExamQuestion.enabled == 1))).scalars().all()
    if not qs:
        return {"ok": False, "msg": "题库未配置，请联系平台", "score": 0, "passed": False}
    norm = {str(k): v for k, v in (answers or {}).items()}
    score = 0
    for q in qs:
        if _answer_correct(q, str(norm.get(str(q.id), ""))):
            score += int(q.score or 0)
    passed = score >= settings.DIST_EXAM_PASS_SCORE
    prev = (await db.execute(select(func.count(ExamRecord.id)).where(
        ExamRecord.user_id == user.id))).scalar() or 0
    rec = ExamRecord(user_id=user.id, distributor_id=(dist.id if dist else None),
                     score=score, passed=1 if passed else 0, answers=answers,
                     attempt_no=int(prev) + 1)
    db.add(rec)
    if passed and dist:
        await db.execute(update(Distributor).where(Distributor.id == dist.id).values(
            exam_passed=1).execution_options(synchronize_session="fetch"))
    await db.flush()
    logger.info(f"[合规考试] user_id={user.id} 第{rec.attempt_no}次 score={score} passed={passed}")
    return {"ok": True, "score": score, "full_score": settings.DIST_EXAM_FULL_SCORE,
            "pass_score": settings.DIST_EXAM_PASS_SCORE, "passed": passed,
            "attempt_no": rec.attempt_no}


async def get_exam_status(db: AsyncSession, user_id: int) -> dict:
    """【未接线·无端点使用本函数】本人考试状态：是否通过、最近一次得分与尝试次数。

    待接线说明见同段 get_exam_paper：考试功能用户侧整体未接线，仅标记、未改动行为。"""
    last = (await db.execute(select(ExamRecord).where(ExamRecord.user_id == user_id)
                             .order_by(ExamRecord.id.desc()).limit(1))).scalar_one_or_none()
    attempts = (await db.execute(select(func.count(ExamRecord.id)).where(
        ExamRecord.user_id == user_id))).scalar() or 0
    return {"passed": bool(last and last.passed == 1), "attempts": int(attempts),
            "last_score": int(last.score) if last else None,
            "pass_score": settings.DIST_EXAM_PASS_SCORE}


# ==================== 第十二/五十六/五条：合规留痕 ====================
async def record_consent(db: AsyncSession, user: User, doc_type: str, doc_version: Optional[str] = None,
                         agreed: bool = True, order_id: Optional[int] = None, ip: Optional[str] = None,
                         user_agent: Optional[str] = None, dist: Optional[Distributor] = None):
    """记录一次合规勾选/签署留痕（第五十九条：文本版本号、时间戳、IP/设备，保存≥3年）。

    agreed=0 的行表示【撤回同意】（个保法第十五条），由 services.consent.withdraw 追加。
    撤回一律是「追加一行」而不是删掉原来的同意行：留痕是法定义务，删行等于销毁证据；
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

    接线（命中侧）：词库维护侧（list/upsert_sensitive_word）本就由 admin.py 调用；
    命中侧此前零调用点、两级处置不生效，现挂在 core 的用户 UGC 入口：
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


# ==================== 第五十条：外部推广账号报备 ====================
async def report_external_account(db: AsyncSession, dist: Distributor, platform: str, account_name: str,
                                  account_url: Optional[str] = None, remark: Optional[str] = None):
    """【未接线·无端点使用本函数】推广员报备用于商业推广的外部账号（status=0 待审）。

    待接线说明（本次死代码清理仅标记、未改动行为）：
    第五十条要求的「推广员报备外部账号」用户侧没有入口：本函数全库零调用点，
    配套的 schemas.ExternalAccountReportRequest 也没有端点使用。审核侧反而已经
    接线（同段 list_external_accounts / review_external_account 由 admin.py 调用），
    所以后台的外部账号审核列表永远为空，审核功能空转。接线时需在
    api/distribution.py 增加报备端点（校验当前用户是推广员后写入）。"""
    row = ExternalAccount(distributor_id=dist.id, user_id=dist.user_id, platform=(platform or "")[:30],
                          account_name=(account_name or "")[:100], account_url=(account_url or "")[:255] or None,
                          status=0, remark=(remark or "")[:200] or None)
    db.add(row)
    await db.flush()
    return row


async def list_external_accounts(db: AsyncSession, distributor_id: Optional[int] = None,
                                 status: Optional[int] = None) -> list:
    stmt = select(ExternalAccount)
    if distributor_id is not None:
        stmt = stmt.where(ExternalAccount.distributor_id == distributor_id)
    if status is not None:
        stmt = stmt.where(ExternalAccount.status == status)
    rows = (await db.execute(stmt.order_by(ExternalAccount.id.desc()).limit(200))).scalars().all()
    return [{"id": a.id, "distributor_id": a.distributor_id, "platform": a.platform,
             "account_name": a.account_name, "account_url": a.account_url, "status": int(a.status or 0),
             "remark": a.remark, "created_at": a.created_at.strftime("%Y-%m-%d %H:%M") if a.created_at else None}
            for a in rows]


async def review_external_account(db: AsyncSession, account_id: int, status: int,
                                  remark: Optional[str] = None, handler: str = "admin"):
    """审核外部账号报备：status 1=通过/2=拒绝。"""
    if status not in (1, 2):
        return False, "审核状态不正确"
    res = await db.execute(update(ExternalAccount).where(ExternalAccount.id == account_id).values(
        status=status, remark=(remark or "")[:200] or None))
    await db.flush()
    if (res.rowcount or 0) == 0:
        return False, "报备记录不存在"
    return True, "已审核"


# ==================== 第五十八条第3款：用户举报工单 ====================
async def create_report_ticket(db: AsyncSession, content: str, reporter_id: Optional[int] = None,
                               target_distributor_id: Optional[int] = None, target_type: Optional[str] = None,
                               evidence=None, contact: Optional[str] = None):
    """【未接线·无端点使用本函数】用户提交举报（可匿名）。status=0 待处理，平台须 24h 内响应。

    待接线说明（本次死代码清理仅标记、未改动行为）：
    第五十八条第3款要求的用户举报通道没有入口：本函数全库零调用点，配套的
    schemas.ReportTicketCreateRequest 也没有端点使用。处置侧已接线（同段
    list_report_tickets / respond_report_ticket / handle_report_ticket 由 admin.py
    调用），所以后台的举报工单列表永远为空，「24h 内响应」的义务既无法被用户
    触发、也无法被后台履行。接线时需增加公开举报端点（reporter_id 可空以支持
    匿名），并复用已有的 respond/handle 流程。"""
    row = ReportTicket(reporter_id=reporter_id, target_distributor_id=target_distributor_id,
                       target_type=(target_type or "distributor")[:30], content=(content or "")[:2000],
                       evidence=evidence, contact=(contact or "")[:100] or None, status=0)
    db.add(row)
    await db.flush()
    return row


async def respond_report_ticket(db: AsyncSession, ticket_id: int, handler: str = "admin"):
    """首次响应（24h 内）：status 0->1 处理中，记 responded_at。"""
    res = await db.execute(update(ReportTicket).where(
        ReportTicket.id == ticket_id, ReportTicket.status == 0).values(
        status=1, handler=handler, responded_at=datetime.now()))
    await db.flush()
    return (res.rowcount or 0) > 0


async def handle_report_ticket(db: AsyncSession, ticket_id: int, handle_result: str,
                               status: int = 2, handler: str = "admin"):
    """核查处置并反馈举报人：status 2=已处置/3=已驳回。"""
    if status not in (2, 3):
        return False, "处置状态不正确"
    res = await db.execute(update(ReportTicket).where(ReportTicket.id == ticket_id).values(
        status=status, handle_result=(handle_result or "")[:500], handler=handler,
        responded_at=func.coalesce(ReportTicket.responded_at, datetime.now())))
    await db.flush()
    if (res.rowcount or 0) == 0:
        return False, "举报工单不存在"
    return True, "已处置"


async def list_report_tickets(db: AsyncSession, status: Optional[int] = None,
                              target_distributor_id: Optional[int] = None) -> list:
    stmt = select(ReportTicket)
    if status is not None:
        stmt = stmt.where(ReportTicket.status == status)
    if target_distributor_id is not None:
        stmt = stmt.where(ReportTicket.target_distributor_id == target_distributor_id)
    rows = (await db.execute(stmt.order_by(ReportTicket.id.desc()).limit(200))).scalars().all()
    return [{"id": t.id, "reporter_id": t.reporter_id, "target_distributor_id": t.target_distributor_id,
             "target_type": t.target_type, "content": t.content, "contact": t.contact,
             "status": int(t.status or 0), "handler": t.handler, "handle_result": t.handle_result,
             "responded_at": t.responded_at.strftime("%Y-%m-%d %H:%M") if t.responded_at else None,
             "created_at": t.created_at.strftime("%Y-%m-%d %H:%M") if t.created_at else None}
            for t in rows]
