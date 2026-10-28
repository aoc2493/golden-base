"""AI 生成合成内容标识（显式标识 + 隐式标识 + 留存元数据）。

法规依据：《人工智能生成合成内容标识办法》（2025 年 9 月 1 日施行）与强制性国标
GB 45438-2025《网络安全技术 人工智能生成合成内容标识方法》。三项义务缺一不可：
  · 显式标识——在呈现给用户的界面上以可感知方式提示「AI 生成」（第四条）；
  · 隐式标识——在内容元数据中写入内容属性、服务提供者名称或编码、内容编号等（第五条、
    GB 45438 表 1/表 2 的 Label、ContentProducer、ProduceID、ContentPropagator、PropagateID）；
  · 日志留存——生成合成内容的日志信息留存不少于六个月（第十一条），见 models.AiGenerationLog。

为什么集中到一个模块：标识文案与元数据字段一旦散落在各渲染器、各接口里，必然漏。
接入方常见做法是只在个别页面写上「由 AI 生成」，同一份内容里其余同样出自大模型的
章节却没有标识——分散实现就会漏标。现在元数据在生成时一次性构造（由插件在生成/交付
钩子中调用 build_ai_meta），随内容落库，接口用 label_payload 展平下发，前端只认这一个
字段渲染标识条，新增内容形态不会再漏。

本模块只构造/解释标识数据：不碰数据库、不发网络请求，可被工具层与服务层安全复用。

【接线状态·读代码前必看】底座不生成任何内容，因此本模块在 app/ 下暂无调用点：
reports.ai_meta 从未被写入、AiGenerationLog 只有清理任务（tasks/scheduler.py 的到期删除）
而没有写入任务。接入方一旦让插件调用模型产内容，就必须补上两处：生成时
`build_ai_meta(...)` 写入 reports.ai_meta 与 AiGenerationLog，下发时用 `label_payload(...)`
展平给前端。只接了 demo 插件（无 AI 内容）的部署不需要配 AI_MARK_*，启动自检对此只告警。
"""
import hashlib
import json
import secrets
from datetime import datetime
from typing import Optional

from app.config import settings

# GB 45438-2025 的内容属性编码：1=人工智能生成合成，0=非生成合成（人工/传统算法）
LABEL_AI = "1"
LABEL_NOT_AI = "0"

# 显式标识文案：只陈述「由谁生成」，内容定性由部署方按自己的业务公示。
AI_LABEL_SHORT = "AI 生成"
AI_LABEL_TEXT = "本内容由人工智能生成合成，可能存在不准确之处，请自行判断"
ALGO_LABEL_SHORT = "算法生成"
ALGO_LABEL_TEXT = "本内容由算法自动计算生成，非人工智能大模型、亦非人工撰写"
# 正文内若含合成图片，需在图片周边另行提示（图片隐式标识由生成方写入）
IMAGE_LABEL_TEXT = "本图片由人工智能生成合成，非真实人物"


def provider_code() -> str:
    """服务提供者编码：优先取配置的统一社会信用代码，留空时用站点标识派生。
    隐式标识要求「名称或编码」二者具备其一即可，两者都给最稳（核查时可直接比对）。"""
    return (settings.AI_MARK_PROVIDER_CODE or "").strip() or f"site-{settings.AI_MARK_SITE_CODE}"


def new_content_id(scene: str) -> str:
    """内容编号（ProduceID）：AIGC-{场景}-{时间}-{随机}。

    必须唯一且可反查——它同时写进隐式标识与生成日志表，是「这条内容出自哪次生成」的
    唯一关联键。用随机后缀而非自增 id：编号会随内容对外下发，自增会把业务量与生成顺序
    暴露给外部（竞品可据此估算日订单量）。
    """
    s = "".join(ch for ch in (scene or "gen") if ch.isalnum() or ch in "_-")[:20] or "gen"
    return f"AIGC-{s}-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3)}"


def prompt_digest(text) -> str:
    """提示词/输入摘要（sha256 截 32 位），生成日志留存用。

    不留原文：提示词里含用户填写的姓名、出生信息等个人信息，全量留存等于把敏感数据复制一份
    进日志表并保留 400 天，与个保法的最小必要原则冲突。摘要足以证明「这次生成用过这份输入」
    （需要复现时用同一输入重算比对即可），也满足「留存可追溯」的监管要求。
    """
    try:
        raw = text if isinstance(text, str) else str(text)
    except Exception:
        raw = ""
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:32]


def build_ai_meta(*, scene: str, ai: bool, content_id: Optional[str] = None,
                  model: Optional[str] = None, engine: Optional[str] = None,
                  generated_at: Optional[datetime] = None,
                  propagate_id: Optional[str] = None,
                  chapters: Optional[list] = None) -> dict:
    """构造随内容落库并对外下发的标识元数据（隐式标识字段 + 显式标识文案）。

    ai=True：内容由生成式 AI（大模型）产出，承担《标识办法》全部义务；
    ai=False：内容由第三方算法计算产出，不属生成式 AI，但仍按同一格式标注「算法生成」，
              避免用户误认为真人撰写——标注从严不会违规，标注缺失才会。
    chapters：AI 参与生成的章节序号（如报告首章为大模型解读、其余为算法原话时传 [0]），
              让标识能精确到章节而不是笼统覆盖全文。
    """
    ts = generated_at or datetime.now()
    cid = content_id or new_content_id(scene)
    meta = {
        # ---- 隐式标识（GB 45438-2025 元数据字段）----
        "Label": LABEL_AI if ai else LABEL_NOT_AI,
        "ContentProducer": settings.AI_MARK_PROVIDER_NAME,
        "ProducerCode": provider_code(),
        "ProduceID": cid,
        "ContentPropagator": settings.AI_MARK_PROVIDER_NAME,
        "PropagateID": propagate_id or cid,
        "ProduceTime": ts.strftime("%Y-%m-%d %H:%M:%S"),
        # ---- 业务侧补充（便于排查与前端渲染，非国标字段）----
        "ai": bool(ai),
        "scene": scene,
        "model": model,
        "engine": engine,
        "ai_chapters": list(chapters) if chapters else [],
        "label_short": AI_LABEL_SHORT if ai else ALGO_LABEL_SHORT,
        "label_text": AI_LABEL_TEXT if ai else ALGO_LABEL_TEXT,
    }
    return meta


def label_payload(meta, *, generated_at: Optional[str] = None) -> dict:
    """接口下发用：把落库元数据整理成前端渲染显式标识所需的扁平字段。

    元数据缺失（本次改动之前生成的历史报告）时按「算法生成」兜底，而不是不标识：
    历史报告同样是自动生成的内容，宁可标注偏保守，也不能出现无任何标识的页面。
    """
    m = meta if isinstance(meta, dict) else {}
    if not m and isinstance(meta, str) and meta.strip():
        # 防御：JSON 列在部分驱动/历史行上会回成字符串（reports.chapters 就为此写了
        # isinstance 判断）。不还原就会把一份真 AI 报告错标成「算法生成」。
        try:
            parsed = json.loads(meta)
            m = parsed if isinstance(parsed, dict) else {}
        except Exception:
            m = {}
    ai = bool(m.get("ai"))
    return {
        "enabled": bool(settings.AI_MARK_ENABLED),
        "ai": ai,
        "label_short": m.get("label_short") or (AI_LABEL_SHORT if ai else ALGO_LABEL_SHORT),
        "label_text": m.get("label_text") or (AI_LABEL_TEXT if ai else ALGO_LABEL_TEXT),
        "image_label": IMAGE_LABEL_TEXT,
        "content_id": m.get("ProduceID"),
        "provider": m.get("ContentProducer") or settings.AI_MARK_PROVIDER_NAME,
        "provider_code": m.get("ProducerCode") or provider_code(),
        "produce_time": m.get("ProduceTime") or generated_at,
        "model": m.get("model"),
        "scene": m.get("scene"),
        "ai_chapters": m.get("ai_chapters") or [],
        # 完整元数据一并下发：内容被复制/转载时隐式标识随内容一起走，
        # 这也是「元数据不得删除、篡改、伪造、隐匿」这条义务的技术兑现。
        "meta": m,
    }
