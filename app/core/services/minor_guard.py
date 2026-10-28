"""A8：年龄门槛与未成年人保护。

义务来源：
  · 《个人信息保护法》第三十一条——处理不满十四周岁未成年人个人信息的，应当取得其父母
    或者其他监护人的同意，并应当制定专门的个人信息处理规则；
  · 《未成年人网络保护条例》第四十三条——网络产品和服务提供者不得向未成年人提供与其
    民事行为能力不符的付费服务；
  · 《民法典》第十七、十八条——十八周岁以上的自然人为成年人。

三道门槛，判据一律「从 birth_date 直接推算周岁」，绝不采信前端传来的年龄或「我已成年」
布尔值（客户端自述的年龄在争议中不构成任何证明）：
  1) 付款人须为成年人（gate_payer）——自报公历出生日期一次，落 users.birth_date，
     每次下单现算周岁。未成年人禁充值。
  2) 解读对象不满十四周岁须监护人同意（gate_bio 的 guardian 分支）——含档案、计算、
     双人解读/双人内容、下单四条会持久化或计费的路径。
  3) 采集他人出生信息须先告知并取得合法性基础承诺（gate_bio 的 third_party 分支）——
     双人解读/双人内容必然包含对方出生信息，属处理第三人个人信息。

为什么集中在本模块：门槛散在各接口里必然出现「下单拦了、建档没拦」的半边合规，而半边
合规在检查中与完全没做同样不合格——它恰好证明平台知道这项义务却只履行了一部分。

【当前状态：三道门槛全部关闭，不拦截任何请求】属主决策 2026-09-11 起 `gate_payer` 与
`gate_bio` 恒返回 None（即「无拦截」），下单/建档/解读不再做年龄判定；启动自检每次都会以
ERROR 级留痕这条决定（见 main._startup_check 的「年龄门槛已关闭」项）。
上面的法定义务描述与本模块保留的判据实现（周岁推算、历法换算、留痕写入）因此处于「能力在、
接线无」状态：重新打开门槛时直接改这两个函数即可，判据不必重写。
本文件里 declare / gate_status / subjects_of 目前没有调用点——它们服务的
/api/user/age-declaration 与 /api/user/age-gate 两个接口已随本次关闭下架（见 api/user.py），
接口下架时保留实现是为了让「重新开启」不必从零补齐留痕链路。
"""
import logging
from datetime import date, datetime
from functools import lru_cache
from typing import Iterable, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.api.common import ErrorCode
from app.core.models import User
from app.core.services import consent as consent_svc

logger = logging.getLogger(__name__)

# 门槛文本版本号：改了文案必须升版本号，否则留痕证明不了「用户当时看到的是哪一版」
# （与分销规则 V1.4 同一口径，见 services/consent.latest_agreed_version 的版本比对）。
GUARD_VERSION = "V1.0"

# 法定年龄门槛。刻意不做成 settings：把法定义务做成 .env 开关，意味着一次配置改动就能
# 静默关掉未成年人保护且不留任何痕迹——那比没有这项保护更难解释。
ADULT_AGE = 18      # 《民法典》第十七条：成年
CHILD_AGE = 14      # 《个人信息保护法》第三十一条：不满十四周岁须监护人同意

# 出生日期合理下限。早于此只可能是误填；放行会让「1900-01-01」这类明显错误值通过成年
# 校验（推算出 126 岁），门槛形同虚设。
MIN_BIRTH_YEAR = 1900

# ---------------- 面向用户的文本（唯一下发口是本模块 gate_status，前端不另抄一份） ----------------
# gate_status 目前无调用点（/api/user/age-gate 已随门槛关闭下架），重新开启门槛时须一并接回。
ADULT_TITLE = "成年声明与年龄确认"
ADULT_TEXT = (
    "本平台的内容与付费服务面向成年人，未成年人不得充值消费。请填写你本人的公历出生年月日："
    "我们据此推算周岁，未满 {adult} 周岁将无法下单支付（免费功能不受影响）。"
    "该信息仅用于履行未成年人保护的法定义务，不用于画像或推荐，不向第三方提供；"
    "提交后不可自助修改（如需更正请联系客服，由平台核验后变更并留痕），"
    "注销账号时随其他个人信息一并删除。"
)
MINOR_TITLE = "未成年人不能充值"
MINOR_TEXT = (
    "你声明的出生日期推算为 {age} 周岁。根据《未成年人网络保护条例》与本平台规则，"
    "未满 {adult} 周岁的用户不能充值购买付费内容与会员。"
    "免费功能仍可正常使用；如你认为年龄推算有误，请联系客服更正。"
)
GUARDIAN_TITLE = "监护人同意（解读对象不满 {child} 周岁）"
GUARDIAN_TEXT = (
    "你填写的出生日期显示该对象不满 {child} 周岁。依据《个人信息保护法》第三十一条，"
    "处理不满十四周岁未成年人的个人信息，应当取得其父母或者其他监护人的同意，"
    "并适用专门的个人信息处理规则。请确认：你是该未成年人的监护人，"
    "或已就此取得其监护人的同意，并已阅读下方专门规则。"
)
THIRD_PARTY_TITLE = "填写他人信息前的告知与承诺"
THIRD_PARTY_TEXT = (
    "为他人生成内容或建档时，可能需要填写对方（伴侣、亲属、朋友）的出生信息，"
    "这属于他人的个人信息。请确认下列之一成立："
    "①你已告知对方本次处理的目的、方式与范围，并取得其同意；"
    "②你与该信息主体之间存在法律规定的其他合法性基础（如监护人为被监护人填写）；"
    "③你填写的是你本人的信息（无需另行取得同意）。"
    "请勿填写你无权处理的他人信息；因你提供的信息不合法而产生的责任由你自行承担。"
)
# 《个人信息保护法》第三十一条明确要求「制定专门的个人信息处理规则」：仅有监护人同意
# 勾选不够，还必须有一份针对未成年人信息的专门规则文本，且要能证明送达过（随门槛下发）。
MINOR_RULES = (
    "未成年人个人信息处理专门规则\n"
    "1. 处理不满十四周岁未成年人的出生年月日时、出生地等信息前，须取得其父母或其他监护人的同意；\n"
    "2. 该类信息仅用于生成该次内容与解读，不用于用户画像、个性化推荐或商业营销，不向第三方提供；\n"
    "3. 监护人可随时撤回同意，撤回后平台停止新的处理（路径：设置 - 隐私授权管理）；\n"
    "4. 监护人可申请删除该未成年人的全部个人信息，或注销账号一并删除；\n"
    "5. 平台不对未成年人开放充值：付款人须为成年人，未成年人不得作为付款主体；\n"
    "6. 本规则文本版本 {version}，修订后将重新取得确认。"
)

GateResult = Tuple[int, str, Optional[dict]]


def _payload(gate: str, title: str, text: str) -> dict:
    """门槛载荷。前端按 gate 决定交互：adult=弹出生日期表单、guardian/third_party=弹勾选、
    minor=终态提示（无可操作项）。文案由后端下发，前端不另抄——门槛文案是向用户作出的
    承诺，两份必然走偏（后端改了门槛前端还在念旧文案，等于虚假告知）。"""
    return {"gate": gate, "title": title, "text": text, "version": GUARD_VERSION,
            "minor_rules": MINOR_RULES.format(version=GUARD_VERSION),
            "adult_age": ADULT_AGE, "child_age": CHILD_AGE}


def _parse_ymd(birth_date) -> Optional[date]:
    """按 YYYY-M-D 解析（容错非零填充，与 schemas._check_date 的正则口径一致）。"""
    s = str(birth_date or "").strip()
    if not s:
        return None
    parts = s.split("-")
    if len(parts) != 3:
        return None
    try:
        return date(int(parts[0]), int(parts[1]), int(parts[2]))
    except (ValueError, TypeError):
        # 正则只保证形如日期，不保证是真实日期：2020-02-31 能过 _DATE_RE 却构造不出 date
        return None


def _mask_birth(birth_date) -> str:
    """日志用出生日期脱敏：只保留年份，隐去月日。

    与 distribution.apply_withdrawal 的 A6 纪律同口径（那里绝不写明文姓名，只记 id 与
    脱敏姓名）：出生日期同属个人信息，本人不满十四周岁时更属敏感个人信息，而日志的
    访问权限通常比库松、留存更久，还会被采集进第三方日志平台——库里为出生信息做了门槛
    保护、注销时一并置空，却把它原文喷进日志等于白做。
    保留年份已足够排查：本模块所有 birth 相关告警要回答的都是「这个值为何推算不出周岁」，
    成因只有早于 MIN_BIRTH_YEAR、晚于参照日、或根本不是真实日期三类；前两类看年份即可
    判定，第三类由「非法值」标记与长度体现，不需要月日。
    """
    s = str(birth_date if birth_date is not None else "").strip()
    if not s:
        return "(空)"
    parts = s.split("-")
    if len(parts) == 3 and parts[0].isdigit():
        return f"{parts[0]}-**-**"
    return f"(非法值 len={len(s)})"


@lru_cache(maxsize=8192)
def _lunar_to_solar_cached(y: int, m: int, d: int) -> Optional[date]:
    """农历→公历，经插件「历法转换器」钩子取得（core 不直接 import 具体插件）。

    历法转换为纯函数（同输入同输出），结果不可变 date，可安全缓存。
    """
    from app.plugins import registry
    conv = registry.lunar_converter()
    if conv is None:
        return None
    return conv(y, m, d)


def solar_of(birth_date, calendar_type: str = "solar") -> Optional[date]:
    """把入参出生信息统一换算成公历日期——年龄只能按公历周岁算。

    农历生日直接按公历年月日解读会偏 1~2 个月（农历正月初一落在公历 1~2 月之间），
    恰好跨过 14/18 岁生日时结论就反了，故农历一律先换算。
    闰月按非闰月处理：入参各路径都没有 is_leap_month 字段（业务侧前置计算读的是
    同一套 params），最大偏差一个月，且只在闰月出生者身上出现——比整段跳过换算安全得多。
    换算失败（超出推算范围等）退回按公历解读并留 WARNING：宁可少拦一个也不能让下单
    链路 500，但必须留痕以便追查。
    """
    d = _parse_ymd(birth_date)
    if d is None:
        return None
    if str(calendar_type or "solar").strip().lower() != "lunar":
        return d
    try:
        converted = _lunar_to_solar_cached(d.year, d.month, d.day)
        if converted is not None:
            return converted
        # 钩子存在但返回 None = 没有任何插件提供农历换算（开源骨架里的 demo 插件即如此）。
        # 与抛异常走同一条退回路径，否则本函数docstring 承诺的「退回按公历 + 留 WARNING」
        # 落不了地：返回 None 会让周岁变成「无法推算」，门槛按性质处理时要么误拦成年人、
        # 要么静默放过，且日志里查不到任何线索。
        logger.warning(f"[年龄门槛] 无插件提供农历换算，退回按公历推算 birth={_mask_birth(birth_date)}")
        return d
    except Exception as e:  # pragma: no cover - 依赖 ephem 的边界情形
        logger.warning(f"[年龄门槛] 农历转公历失败，退回按公历推算 birth={_mask_birth(birth_date)} err={e}")
        return d


def age_of(birth_date, calendar_type: str = "solar", ref=None) -> Optional[int]:
    """周岁。生日当天即满（与户籍口径一致）。

    返回 None 表示「无法推算」：空值、格式非法、非真实日期、早于 MIN_BIRTH_YEAR、
    或晚于参照日（未来出生日期）。调用方对 None 的处理方向按门槛性质区分——付款人门槛
    按「未声明」拦住，本人门槛按「可能是未成年人」保守要求监护人同意；两处都绝不把
    无法推算当成已成年。
    """
    b = solar_of(birth_date, calendar_type)
    if b is None:
        return None
    now = ref or datetime.now()
    r = now.date() if isinstance(now, datetime) else now
    if b > r or b.year < MIN_BIRTH_YEAR:
        return None
    return r.year - b.year - ((r.month, r.day) < (b.month, b.day))


def subjects_of(*pairs) -> list:
    """把 (birth_date, calendar_type) 组装成门槛入参，顺手丢掉空出生信息。

    实时测算、日常工具等功能没有出生信息；双人解读/双人内容有两份；档案与单次测算各有一份。
    统一成一个列表口径，避免每个调用点各写一遍「有没有 birth_date 键」的判断。
    """
    out = []
    for p in pairs:
        if not p:
            continue
        bd = p[0] if isinstance(p, (list, tuple)) else (p.get("birth_date") if isinstance(p, dict) else None)
        cal = p[1] if isinstance(p, (list, tuple)) and len(p) > 1 else (
            p.get("calendar_type") if isinstance(p, dict) else "solar")
        if str(bd or "").strip():
            out.append((str(bd).strip(), cal or "solar"))
    return out


# ==================== 门槛一：付款人成年 ====================
def gate_payer(user: User) -> Optional[GateResult]:
    """下单前的付款人年龄门槛。返回 None=放行，否则 (code, msg, data) 供接口直接 error()。

    每次现算周岁，而不是存一个 is_adult 布尔：存标记就需要一个「满 18 后翻标记」的后台
    作业，漏跑一天就把成年人一直拦在门外；现算则 17 岁声明的人在自己 18 岁生日当天自动
    放行，不需要任何作业，也不会出现「标记与实际年龄不一致」这个新的差错源。
    """
    # 2026-09-11 平台属主决策：成年声明门槛前后端一起关闭（合规风险由产品侧承担，
    # 决策已留痕于属主会话）。本函数恒放行；下方 declare/留痕能力保留但不再有任何拦截面。
    return None


async def declare(db: AsyncSession, user: User, birth_date: str,
                  ip: Optional[str] = None, user_agent: Optional[str] = None):
    """提交成年声明。返回 (ok, msg, data)。

    未成年人的声明【同样落库】：不写库就等于允许反复改口试探——填 2015 年被拦、改成
    1990 年即通过，门槛一次就被绕过且不留痕迹。写库后该账号在满 18 岁之前一直拦，
    生日当天自动放行（gate_payer 现算），既堵死试探又不需要人工干预。

    已声明过则拒绝自助修改。自助改口与反复试探在数据上无法区分，唯一可靠的口径是
    「声明即承诺，承诺不可自助变更」；填错由客服核验后经后台更正（写审计日志）。
    提交同一个值视为幂等重放，直接返回当前状态而不是报错。
    """
    d = solar_of(birth_date, "solar")   # 声明只收公历：农历自报年龄无法向监管复现
    if d is None:
        return False, "出生日期格式非法，应为公历 YYYY-MM-DD", None
    if d.year < MIN_BIRTH_YEAR:
        return False, f"出生日期不能早于 {MIN_BIRTH_YEAR} 年，请核对后重新填写", None
    if d > datetime.now().date():
        return False, "出生日期不能晚于今天", None
    norm = d.isoformat()
    old = str(user.declared_birth_date or "").strip()
    age = age_of(norm, "solar")
    if old:
        if old != norm:
            # locked 而不是 code：这不是未成年拦截，而是「声明不可自助变更」，前端该提示联系客服
            return False, ("出生日期已声明过，不能自助修改。如填写有误请联系客服，"
                           "由平台核验后更正（更正会留痕）。"), {"declared": True, "locked": True}
    else:
        user.declared_birth_date = norm
        user.age_declared_at = datetime.now()
        # 留痕在年龄判断之前：无论声明结果是成年还是未成年，「平台在 T 时点取得过声明、
        # 文本版本为 V」这件事本身就是要保存的证据。
        await consent_svc.sign(db, user, consent_svc.DOC_ADULT, doc_version=GUARD_VERSION,
                               ip=ip, user_agent=user_agent)
        logger.info(f"[年龄门槛] 成年声明已记录 user_id={user.id} adult={age is not None and age >= ADULT_AGE}")
    if age is None or age < ADULT_AGE:
        # code 随 data 一起回给接口层：「未成年被禁充值」与「出生日期格式错」在前端是完全
        # 不同的交互（前者是终态提示、后者让用户重填），归进同一个 PARAM_ERROR 就分不开了。
        return False, MINOR_TEXT.format(age=(age if age is not None else 0), adult=ADULT_AGE), {
            "declared": True, "adult": False, "age": age, "code": ErrorCode.MINOR_BLOCKED,
            "payload": _payload("minor", MINOR_TITLE,
                                MINOR_TEXT.format(age=(age if age is not None else 0), adult=ADULT_AGE))}
    return True, "成年声明已记录", {"declared": True, "adult": True, "age": age}


# ==================== 门槛二/三：他人出生信息告知 + 监护人同意 ====================
async def _ensure_third_party(db: AsyncSession, user: User, consented: bool,
                             ip: Optional[str], user_agent: Optional[str]) -> Optional[GateResult]:
    """采集他人出生信息前的告知与合法性基础确认（账号级一次，按版本号判）。

    账号级而不是每单一次：这是「你有权处理这些信息」的承诺，不随每一次计算变化，
    每单都弹会让用户养成闭眼勾选的习惯——那恰恰是告知同意制度要防止的。
    按版本号判（latest_agreed_version）而不是「有没有同意过」：文本改版后旧确认不能
    继续代表对新文本的同意，与规则变更公示同一口径。
    """
    agreed = await consent_svc.latest_agreed_version(db, user.id, consent_svc.DOC_THIRD_PARTY)
    if agreed == GUARD_VERSION:
        return None
    if not consented:
        return (ErrorCode.CONSENT_REQUIRED, "请先确认他人信息的告知与承诺",
                _payload("third_party", THIRD_PARTY_TITLE, THIRD_PARTY_TEXT))
    await consent_svc.sign(db, user, consent_svc.DOC_THIRD_PARTY, doc_version=GUARD_VERSION,
                           ip=ip, user_agent=user_agent, reaffirm=True)
    logger.info(f"[年龄门槛] 他人出生信息告知已确认 user_id={user.id} version={GUARD_VERSION}")
    return None


async def gate_bio(db: AsyncSession, user: User, subjects: Iterable, *,
                   guardian_consent: bool = False, third_party_consent: bool = False,
                   ip: Optional[str] = None, user_agent: Optional[str] = None,
                   order_id: Optional[int] = None) -> Optional[GateResult]:
    """一次出生信息输入的两道门。subjects 为 [(birth_date, calendar_type), ...]（可为空）。

    返回 None=放行；否则 (code, msg, data)。data.gate 告诉前端该弹哪种交互，
    前端补齐对应的 *_consent 标记后原样重放请求即可通过——不做「先预检再提交」两次
    往返：预检与真实提交之间状态可能变化，而以真实请求的返回驱动交互天然一致。
    """
    # 2026-09-11 平台属主决策：他人出生信息告知 + 监护人同意两道门槛前后端一起关闭
    # （合规风险由产品侧承担，决策已留痕于属主会话）。恒放行，不再回 1008、不再签留痕。
    return None


async def gate_status(db: AsyncSession, user: User) -> dict:
    """/api/user/age-gate 的数据：当前门槛状态 + 全部门槛文本。

    前端用它在打开支付弹层/建档表单前预渲染提示（少一次「提交-被拦-弹窗-重放」的往返），
    但真正的拦截一律在服务端每次请求时执行——预检结果绝不能被当成放行依据。
    """
    bd = str(user.declared_birth_date or "").strip()
    age = age_of(bd, "solar") if bd else None
    tp = await consent_svc.latest_agreed_version(db, user.id, consent_svc.DOC_THIRD_PARTY)
    return {
        "version": GUARD_VERSION, "adult_age": ADULT_AGE, "child_age": CHILD_AGE,
        "declared": bool(bd), "birth_date": bd or None, "age": age,
        "adult": bool(age is not None and age >= ADULT_AGE),
        "declared_at": user.age_declared_at.strftime("%Y-%m-%d %H:%M") if user.age_declared_at else None,
        "third_party_confirmed": tp == GUARD_VERSION,
        "texts": {
            "adult": _payload("adult", ADULT_TITLE, ADULT_TEXT.format(adult=ADULT_AGE)),
            "guardian": _payload("guardian", GUARDIAN_TITLE.format(child=CHILD_AGE),
                                 GUARDIAN_TEXT.format(child=CHILD_AGE)),
            "third_party": _payload("third_party", THIRD_PARTY_TITLE, THIRD_PARTY_TEXT),
            "minor": _payload("minor", MINOR_TITLE, MINOR_TEXT.format(age=(age or 0), adult=ADULT_AGE)),
        },
    }
