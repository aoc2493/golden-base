"""A6：个人信息处理同意的留痕、查询与撤回（《个人信息保护法》第十五、十六条）。

为什么单独一个模块、而不是塞进 distribution_compliance：那张 compliance_consents 表原先
只承载分销文书（承诺书 / 支付前免责勾选 / 规则变更确认），而「撤回同意」是面向全体用户的
隐私权利，义务来源、生效后果、面向的页面都不同。两者共用同一张留痕表（字段完全够用，且
留痕口径统一，按 user_id 一次就能查全一个人的所有同意历史），但业务语义分开——避免以后
改分销规则时误伤隐私同意链路，反之亦然。

第十五条：个人有权撤回其同意，处理者应当提供便捷的撤回方式。
第十六条：不得以个人撤回同意为由拒绝提供产品或服务，但「处理个人信息属于提供产品或者
服务所必需」的除外。本产品的内容解读必须使用出生年月日时与出生地，正属该例外，因此撤回
后停止新的下单/新的信息收集是合法的；但同时必须给出两条出路（重新同意恢复服务、或注销
账号删除数据），不能让用户撤回之后卡死在既用不了又删不掉的中间态。

撤回为什么不用「删掉同意行」实现：留痕是法定义务（第五十九条 ≥3 年、个保法要求可证明
取得同意的时间方式），删行等于销毁证据。正确做法是追加一行 agreed=0，用「最新一行」表示
当前状态——这也是 has_signed 必须改成最新行语义的原因（见 distribution_compliance）。
"""
import logging
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.models import ComplianceConsent, Distributor, User, ViolationRecord
from app.core.services import distribution_compliance as dc

logger = logging.getLogger(__name__)

# 个人信息处理同意（隐私政策）。这是「撤回同意」的主要对象：撤回后停止新的处理。
DOC_PRIVACY = "privacy_policy"
DOC_COMMITMENT = dc.DOC_COMMITMENT                # 《合规推广承诺书》
DOC_PAYMENT_DISCLAIMER = dc.DOC_PAYMENT_DISCLAIMER  # 支付前免责与虚拟商品规则确认
DOC_RULE_CHANGE = dc.DOC_RULE_CHANGE              # 推广规则重大不利变更确认

# A8：年龄门槛与未成年人保护（services/minor_guard）。三类留痕共用本表，但语义不同：
#   adult_declaration  成年声明（事实声明，不可撤回：撤回等于「我刚才没说过自己多大」）
#   guardian_consent   不满十四周岁未成年人的监护人同意（个保法第三十一条，可撤回）
#   third_party_bio    填写他人出生信息前的告知与合法性基础承诺（可撤回，按版本号判）
# 版本号在 minor_guard.GUARD_VERSION：文本改版必须升版本号，旧确认不能代表对新文本的同意。
DOC_ADULT = "adult_declaration"
DOC_GUARDIAN = "guardian_consent"
DOC_THIRD_PARTY = "third_party_bio"

# 授权项元数据。前端「隐私授权管理」页直接渲染本表，不在 JS 里另抄一份文案：
# 撤回后果是向用户作出的承诺，两份文案必然走偏（改了后端后果却忘改前端说明，用户看到的
# 承诺就成了假的），所以文案只此一份、由接口下发。
CONSENT_ITEMS = [
    {
        "doc_type": DOC_PRIVACY,
        "title": "个人信息处理同意（隐私政策）",
        "purpose": "用于生成你请求的解读内容：你提交的个人信息",
        "revocable": True,
        "revoke_effect": ("撤回后将停止新的信息收集与付费服务：无法新建个人档案、无法下单购买内容。"
                          "已生成的历史报告与订单/退款凭证依法保留（财务凭证与合规留痕有法定保存义务）。"
                          "如需彻底停止处理并删除个人数据，请注销账号；如想继续使用，可重新同意。"),
    },
    {
        "doc_type": DOC_COMMITMENT,
        "title": "《合规推广承诺书》",
        "purpose": "用于开通并维持推广（分销）资格",
        "revocable": True,
        "revoke_effect": ("撤回后立即停用你的专属推广链接与二维码，不再新增推广关系；"
                          "已产生的推广服务费仍可正常结算与提现（那是你已取得的劳动报酬，不因撤回而作废）。"
                          "如想恢复推广，重新签署承诺书即可。"),
    },
    {
        "doc_type": DOC_PAYMENT_DISCLAIMER,
        "title": "支付前免责与虚拟商品规则确认",
        "purpose": "下单支付时对退款规则、虚拟内容属性的确认留痕",
        "revocable": False,
        "revoke_effect": ("这是合同条款确认，不是个人信息处理同意，因此不适用撤回；"
                          "如需救济，可按退款规则申请退款，或注销账号删除个人数据。"),
    },
    {
        "doc_type": DOC_RULE_CHANGE,
        "title": "推广规则重大不利变更确认",
        "purpose": "推广规则发生对你不利的重大变更时的单独确认留痕",
        "revocable": False,
        "revoke_effect": ("这是规则确认留痕，不是个人信息处理同意，因此不适用撤回；"
                          "如不接受变更，可撤回《合规推广承诺书》停止推广，或注销账号。"),
    },
    {
        "doc_type": DOC_ADULT,
        "title": "成年声明（年龄门槛）",
        "purpose": "用于履行未成年人保护义务：判定付款人是否已满十八周岁",
        "revocable": False,
        "revoke_effect": ("这是事实声明而非个人信息处理同意，不适用撤回。出生日期提交后不可自助修改"
                          "（否则未成年人只要反复改口就能绕过充值门槛）；如填写有误请联系客服核验更正，"
                          "或注销账号删除个人信息（声明行为本身的留痕依法保留）。"),
    },
    {
        "doc_type": DOC_GUARDIAN,
        "title": "监护人同意（不满十四周岁未成年人）",
        "purpose": "处理不满十四周岁未成年人的个人信息前取得监护人同意（个保法第三十一条）",
        "revocable": True,
        "revoke_effect": ("撤回后不再为该未成年人生成新的内容，也不能再新建、修改其个人档案；"
                          "已生成的历史报告与订单凭证依法保留。如想继续使用，重新确认监护人同意即可；"
                          "如需彻底删除该未成年人的个人信息，请删除其档案或联系客服。"),
    },
    {
        "doc_type": DOC_THIRD_PARTY,
        "title": "他人个人信息的告知与承诺",
        "purpose": "为他人生成内容或建档时，确认你已告知对方并取得同意或具有其他合法性基础",
        "revocable": True,
        "revoke_effect": ("撤回后无法再提交新的个人信息（包括你本人的）：平台无法从一份信息里分辨"
                          "哪些是他人的，只能整体停止新的收集。已生成的历史报告与订单凭证依法保留。"
                          "如想继续使用，重新确认即可；如需删除个人数据，请注销账号。"),
    },
]
_SPEC = {it["doc_type"]: it for it in CONSENT_ITEMS}

# 违规处置中「会造成断链/资格停用」的动作，与「解除」动作。用于判断当前的 link_disabled=1
# 到底是用户自己撤回承诺书造成的（可自助恢复），还是平台违规处置造成的（必须后台解除）。
_VIOLATION_OFF_ACTIONS = ("link_off", "freeze", "terminate", "exit")
_VIOLATION_ON_ACTIONS = ("link_on", "unfreeze", "restore")


async def _link_off_by_violation(db: AsyncSession, distributor_id: int) -> bool:
    """当前断链是否由违规处置造成（而不是用户自己撤回承诺书）。

    取最近一条相关处置记录判定：停用类在后 → 处置生效中；解除类在后或从无记录 →
    不是处置造成的。绝不能让用户「重新点一次同意」就把违规断链/冻结解掉：重新签署
    承诺书是用户随时能自助完成的动作，若能解处罚，第五十八/六十条的处置形同虚设。
    """
    rec = (await db.execute(select(ViolationRecord).where(
        ViolationRecord.distributor_id == distributor_id,
        ViolationRecord.status == "applied",
        ViolationRecord.action.in_(_VIOLATION_OFF_ACTIONS + _VIOLATION_ON_ACTIONS))
        .order_by(ViolationRecord.id.desc()).limit(1))).scalar_one_or_none()
    return rec is not None and (rec.action or "") in _VIOLATION_OFF_ACTIONS


def _fmt(dt) -> Optional[str]:
    return dt.strftime("%Y-%m-%d %H:%M") if dt else None


async def _latest_rows(db: AsyncSession, user_id: int) -> dict:
    """取该用户每类文书的【最新一行】。

    两次查询而不是把全部留痕行拉进内存：payment_disclaimer 每下一单就有一行，活跃用户
    可能几百行，为了拿 4 个最新状态把全表行实例化是自找开销。先 group by 取 max(id)
    与条数，再按 id 一次取回这几行。
    返回 {doc_type: {"row": ComplianceConsent|None, "records": int}}。
    """
    agg = (await db.execute(
        select(ComplianceConsent.doc_type, func.max(ComplianceConsent.id),
               func.count(ComplianceConsent.id))
        .where(ComplianceConsent.user_id == user_id)
        .group_by(ComplianceConsent.doc_type))).all()
    out = {dt: {"row": None, "records": int(cnt)} for dt, _mid, cnt in agg}
    ids = [mid for _dt, mid, _cnt in agg if mid]
    if ids:
        rows = (await db.execute(select(ComplianceConsent).where(
            ComplianceConsent.id.in_(ids)))).scalars().all()
        for r in rows:
            if r.doc_type in out:
                out[r.doc_type]["row"] = r
    return out


async def get_overview(db: AsyncSession, user: User) -> dict:
    """「隐私授权管理」页数据：每类授权的当前状态 + 能否撤回 + 撤回后果。

    agreed 用三态而不是布尔：None=从未留痕过（存量用户在本次改动前没有任何同意记录），
    True=当前处于同意状态，False=已撤回。前端据此显示「未记录/已同意/已撤回」三种标签——
    把「从未记录」显示成「已撤回」会吓到用户，显示成「已同意」则是虚假陈述。
    """
    latest = await _latest_rows(db, user.id)
    items = []
    for spec in CONSENT_ITEMS:
        dt = spec["doc_type"]
        info = latest.get(dt) or {"row": None, "records": 0}
        row = info["row"]
        agreed = None if row is None else bool(int(row.agreed or 0) == 1)
        items.append({
            **spec,
            "agreed": agreed,
            "agreed_at": _fmt(row.agreed_at) if row else None,
            "doc_version": row.doc_version if row else None,
            "records": info["records"],
        })
    return {"list": items,
            "note": "撤回同意后我们不会删除法定留痕记录（用于证明取得同意的方式与时间），"
                    "但会立即停止该项授权对应的处理。"}


async def sign(db: AsyncSession, user: User, doc_type: str, doc_version: Optional[str] = None,
               agreed: bool = True, order_id: Optional[int] = None, ip: Optional[str] = None,
               user_agent: Optional[str] = None, reaffirm: bool = False):
    """记录一次同意/勾选（含撤回后的重新同意）。doc_type 必须在 CONSENT_ITEMS 内。

    reaffirm：是否为用户在「隐私授权管理」页上的【明示】重新同意。
    这个参数存在的唯一理由是拦住「默示同意覆盖明示撤回」：支付弹层的口径是“支付即
    代表同意隐私政策”，前端在点付款时会顺手补记一条 privacy_policy 同意——如果用户刚刚
    才撤回过，这条自动补记就会把他的撤回静默抹除，用户从界面上根本看不到自己“又被
    同意”了。明示撤回只能由明示同意推翻，故未带 reaffirm 时拒绝覆盖撤回状态。
    """
    spec = _SPEC.get(doc_type)
    if not spec:
        return False, "授权项不存在"
    if agreed and doc_type == DOC_PRIVACY and not reaffirm:
        latest = (await _latest_rows(db, user.id)).get(doc_type) or {}
        row = latest.get("row")
        if row is not None and int(row.agreed or 0) != 1:
            return False, ("你已撤回个人信息处理同意。如需恢复使用，请在「设置 - 隐私授权管理」"
                           "中重新同意；如需删除个人数据，请注销账号。")
    dist = None
    if doc_type == DOC_COMMITMENT:
        dist = (await db.execute(select(Distributor).where(
            Distributor.user_id == user.id))).scalar_one_or_none()
    rec = await dc.record_consent(db, user, doc_type, doc_version=doc_version, agreed=agreed,
                                  order_id=order_id, ip=ip, user_agent=user_agent, dist=dist)
    note = None
    # 重新签署承诺书 → 恢复专属链接（撤回时置 1）。但违规处置造成的断链不在此列：
    # 那必须由后台审核解除，用户自己点一次「同意」就把处罚解掉是不可接受的。
    if doc_type == DOC_COMMITMENT and agreed and dist and int(dist.link_disabled or 0) == 1:
        if await _link_off_by_violation(db, dist.id):
            note = ("承诺书已重新签署；但你的推广资格正处于违规处置中，"
                    "专属链接需平台审核后才能恢复，请联系客服。")
            logger.warning(f"[同意留痕] 重签承诺书但违规断链生效中，不恢复链接 "
                           f"user_id={user.id} distributor_id={dist.id}")
        else:
            await db.execute(update(Distributor).where(Distributor.id == dist.id)
                             .values(link_disabled=0).execution_options(synchronize_session="fetch"))
            logger.info(f"[同意留痕] 重新签署承诺书，恢复专属链接 user_id={user.id} distributor_id={dist.id}")
    return True, {"note": note, "id": rec.id}


async def withdraw(db: AsyncSession, user: User, doc_type: str, ip: Optional[str] = None,
                   user_agent: Optional[str] = None):
    """第十五条：撤回同意。追加一行 agreed=0 并执行对应的停止处理动作。

    返回 (ok, msg)。不可撤回的文书返回失败并如实说明原因——给一个点了没有任何效果的
    「撤回」按钮，比不提供按钮更糟（用户会以为已经撤回了）。
    """
    spec = _SPEC.get(doc_type)
    if not spec:
        return False, "授权项不存在"
    if not spec["revocable"]:
        return False, spec["revoke_effect"]
    latest = (await _latest_rows(db, user.id)).get(doc_type) or {}
    row = latest.get("row")
    if row is None:
        return False, "该项授权从未记录过同意，无需撤回"
    if int(row.agreed or 0) != 1:
        return False, "该项授权已处于撤回状态"
    dist = None
    if doc_type == DOC_COMMITMENT:
        dist = (await db.execute(select(Distributor).where(
            Distributor.user_id == user.id))).scalar_one_or_none()
    await dc.record_consent(db, user, doc_type, doc_version=row.doc_version, agreed=False,
                            ip=ip, user_agent=user_agent, dist=dist)
    if doc_type == DOC_COMMITMENT:
        if dist:
            # 只断链（停止新增推广关系），不冻结 status：冻结会连带锁死提现
            # （apply_withdrawal 以 _dist_frozen 为闸门），把用户已挣到的推广服务费扣在
            # 平台手里。撤回同意是停止继续处理，不是没收已取得的财产。
            await db.execute(update(Distributor).where(Distributor.id == dist.id).values(
                link_disabled=1,
                # 档案字段反映当前状态：承诺书已撤回就不该还挂着「签署时点」。
                # 历史签署事实由 compliance_consents 的留痕行承载，不会丢。
                consent_signed_at=None).execution_options(synchronize_session="fetch"))
        logger.info(f"[撤回同意] 合规推广承诺书已撤回，专属链接停用 user_id={user.id}")
    elif doc_type == DOC_PRIVACY:
        logger.info(f"[撤回同意] 个人信息处理同意已撤回，停止新的收集与下单 user_id={user.id}")
    return True, spec["revoke_effect"]


async def latest_agreed_version(db: AsyncSession, user_id: int, doc_type: str) -> Optional[str]:
    """该文书【当前生效】留痕的文本版本号（最新一行为同意时返回其版本，否则 None）。

    规则变更确认必须按版本号判：只判「有没有确认过」会把 V1.3 的确认当成 V1.4 的确认，
    用户其实从未见过新口径，公示留痕就失去意义（也无法向监管证明哪一版已送达）。
    """
    rec = (await db.execute(select(ComplianceConsent).where(
        ComplianceConsent.user_id == user_id, ComplianceConsent.doc_type == doc_type)
        .order_by(ComplianceConsent.id.desc()).limit(1))).scalar_one_or_none()
    if rec is None or int(rec.agreed or 0) != 1:
        return None
    return rec.doc_version


async def ensure_privacy_consent(db: AsyncSession, user_id: int) -> Optional[str]:
    """新的个人信息处理入口的前置校验。返回 None=放行，返回字符串=拒绝原因。

    只有「明确存在撤回记录（最新一行 agreed=0）」才拦截；从未留痕过（本次改动之前的全部
    存量用户）一律放行。这一点是硬要求：若把「没有同意行」也当成未同意，上线瞬间所有老
    用户都下不了单，等于自己制造一次全站事故。他们的同意此前已通过支付页勾选与持续使用
    取得，只是没有落库留痕，前端会在下一次支付时补记。

    拦截点只放在「新的处理请求」上（下单、新建业务档案），不逐一插桩到每个计算/解读接口：
    已成交订单必须继续履约交付（收了钱不给货比隐私问题更严重），而已有数据的彻底停止处理
    与删除由注销账号完成。
    """
    row = (await db.execute(select(ComplianceConsent).where(
        ComplianceConsent.user_id == user_id,
        ComplianceConsent.doc_type == DOC_PRIVACY)
        .order_by(ComplianceConsent.id.desc()).limit(1))).scalar_one_or_none()
    if row is not None and int(row.agreed or 0) != 1:
        return ("你已撤回个人信息处理同意，平台已停止新的信息收集与付费服务。"
                "如需继续使用，请在「设置 - 隐私授权管理」中重新同意；"
                "如需删除个人数据，请注销账号。")
    return None
