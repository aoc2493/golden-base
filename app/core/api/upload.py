from fastapi import APIRouter, Depends, UploadFile, File, Request
from app.core.models import User
from app.core.auth import get_current_user, redis_client
from app.core.utils.oss import oss_service, probe_image_size, MAX_UPLOAD_PIXELS
from app.config import settings
from app.core.api.common import success, error, ErrorCode, get_client_ip, redis_rate_limit

router = APIRouter(prefix="/upload", tags=["上传"])
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/jpg"}
MAX_AVATAR_SIZE = 2 * 1024 * 1024
MAX_FEEDBACK_SIZE = 5 * 1024 * 1024
_READ_CHUNK = 64 * 1024

# 文件头魔数白名单（content-type 可伪造，必须校验真实文件头）
def _is_real_image(content: bytes) -> bool:
    if len(content) < 12:
        return False
    # JPEG: FF D8 FF
    if content[:3] == b"\xff\xd8\xff":
        return True
    # PNG: 89 50 4E 47 0D 0A 1A 0A
    if content[:8] == b"\x89PNG\r\n\x1a\n":
        return True
    # WEBP: RIFF????WEBP
    if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return True
    return False


async def _read_limited(file: UploadFile, max_size: int):
    """分块读取并在超限处立即中止。
    原实现 await file.read() 会先把整个请求体载入内存再判大小：Content-Length 可随意
    声明，实际体积只受服务器 body 上限约束，并发发送大量超大文件即可直接耗尽内存。
    这里最多多读 1 字节用于判定超限，多余部分不再进入内存。"""
    buf = bytearray()
    remaining = max_size + 1
    while remaining > 0:
        chunk = await file.read(min(_READ_CHUNK, remaining))
        if not chunk:
            break
        buf.extend(chunk)
        remaining -= len(chunk)
    if len(buf) > max_size:
        return None, "图片大小超出限制"
    return bytes(buf), None


async def _validate(file: UploadFile, max_size: int):
    if file.content_type not in ALLOWED_TYPES:
        return None, "仅支持 jpg/png/webp 格式"
    content, err = await _read_limited(file, max_size)
    if err:
        return None, err
    if not _is_real_image(content):
        return None, "文件内容不是有效图片，禁止上传"
    # 体积上限管不住像素数（详见 oss.MAX_UPLOAD_PIXELS 的注释与实测数据），
    # 必须在解码之前按图片头里的声明尺寸拦截。放在这一层而不是只放在压缩环节，
    # 是为了给出可操作的提示：压缩失败一律返回 None，接口只会说「上传失败，请稍后重试」，
    # 拿着超大图的用户会一直重试下去。
    size = probe_image_size(content)
    if not size or size[0] <= 0 or size[1] <= 0 or size[0] * size[1] > MAX_UPLOAD_PIXELS:
        return None, "图片尺寸过大或文件已损坏，请裁剪后重试"
    return content, None


async def _upload_guard(request: Request, user: User, kind: str):
    """上传限流：图片压缩走线程池（PIL thumbnail + save），无限流时可被当作 CPU/IO 放大器"""
    ip = get_client_ip(request)
    key = f"rate:upload:{kind}:{user.id}:{ip}"
    allowed = await redis_rate_limit(redis_client, key, settings.RATE_LIMIT_UPLOAD_PER_MIN, 60)
    if not allowed:
        return error(ErrorCode.RATE_LIMIT, "上传过于频繁，请稍后再试")
    return None


@router.post("/avatar")
async def upload_avatar(request: Request, file: UploadFile = File(...), user: User = Depends(get_current_user)):
    limited = await _upload_guard(request, user, "avatar")
    if limited:
        return limited
    content, err = await _validate(file, MAX_AVATAR_SIZE)
    if err:
        return error(ErrorCode.FILE_INVALID, err)
    url = await oss_service.upload_avatar(content, file.filename or "avatar.jpg")
    if not url:
        return error(ErrorCode.UPLOAD_FAILED, "上传失败，请稍后重试")
    return success({"url": url})


@router.post("/feedback")
async def upload_feedback_image(request: Request, file: UploadFile = File(...), user: User = Depends(get_current_user)):
    limited = await _upload_guard(request, user, "feedback")
    if limited:
        return limited
    content, err = await _validate(file, MAX_FEEDBACK_SIZE)
    if err:
        return error(ErrorCode.FILE_INVALID, err)
    url = await oss_service.upload_feedback_image(content, file.filename or "feedback.jpg")
    if not url:
        return error(ErrorCode.UPLOAD_FAILED, "上传失败，请稍后重试")
    return success({"url": url})
