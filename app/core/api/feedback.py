from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.models import User, Feedback
from app.core.schemas import FeedbackRequest, GuestFeedbackRequest
from app.core.auth import get_current_user, redis_client
from app.config import settings
from app.core.api.common import success, error, ErrorCode, get_client_ip, redis_rate_limit
from app.core.services import distribution_compliance as compliance_svc

router = APIRouter(prefix="/feedback", tags=["反馈"])


@router.post("")
async def submit_feedback(
    req: FeedbackRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """提交意见反馈"""
    # 无限流的写入口：每次提交都是一条 INSERT，可被脚本刷满 feedbacks 表（存储滥用），
    # 也会把后台反馈列表淹掉。按用户+IP 双维度限流。
    ip = get_client_ip(request)
    allowed = await redis_rate_limit(
        redis_client, f"rate:feedback:{user.id}:{ip}", settings.RATE_LIMIT_FEEDBACK_PER_MIN, 60)
    if not allowed:
        return error(ErrorCode.RATE_LIMIT, "提交过于频繁，请稍后再试")

    # M3③（第五十七/五十八条）：反馈内容落库前过敏感词。一级拦截词 blocked → 拒绝提交；
    # 二级预警词 warned → 放行（反馈是单向提交给平台，仅在返回里文字提示，不打断）。
    sw = await compliance_svc.check_sensitive(db, req.content)
    if sw["blocked"]:
        return error(ErrorCode.CONTENT_VIOLATION, "反馈内容含违规信息，请修改后再提交")
    feedback = Feedback(
        user_id=user.id,
        type=req.type,
        content=req.content,
        images=req.images,
        status="pending",
    )
    db.add(feedback)
    await db.flush()
    return success(msg="反馈含疑似违规内容，请注意规范用词" if sw.get("warned") else "success")


@router.post("/guest")
async def submit_guest_feedback(
    req: GuestFeedbackRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """联系页在线留言（免登录）。

    为何单开一个入口而不是放开原 /feedback：
      · 原接口绑定登录用户，用于产品内意见反馈，放开后无法归因、也无法按用户限流；
      · 联系页访客绝大多数未登录，只能靠 IP 限流兜底（10 分钟 3 条）；
      · feedbacks.user_id 非空无默认，游客统一记 0，后台按 type='contact' 筛选即可。
    """
    ip = get_client_ip(request)
    allowed = await redis_rate_limit(redis_client, f"rate:feedback:guest:{ip}", 3, 600)
    if not allowed:
        return error(ErrorCode.RATE_LIMIT, "提交过于频繁，请稍后再试")

    sw = await compliance_svc.check_sensitive(db, req.content)
    if sw["blocked"]:
        return error(ErrorCode.CONTENT_VIOLATION, "留言内容含违规信息，请修改后再提交")

    content = f"【在线留言】姓名：{req.name}｜联系方式：{req.contact}\n内容：{req.content}"
    feedback = Feedback(user_id=0, type="contact", content=content, status="pending")
    db.add(feedback)
    await db.flush()
    return success(msg="留言已提交，我们会尽快与您联系")
