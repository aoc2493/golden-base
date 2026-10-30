"""
腾讯云 COS 对象存储（异步包装，避免阻塞事件循环）
对象存储用腾讯云 COS；桶名/Region/CDN 域名全部由配置提供，代码里不预设任何真实桶
接口保持不变：upload_avatar / upload_feedback_image
"""
import io
import uuid
import asyncio
import logging
from typing import Optional
from PIL import Image
from app.config import settings

logger = logging.getLogger(__name__)

# 对象键扩展名与 ContentType 一律由真实图片格式推导，不采信用户传入的 filename。
# 直接拼接 filename 后缀可构造 .html/.svg/.php 等对象键；当存储桶或 CDN
# 开启静态网站托管、按扩展名推断类型时，可能造成内容执行风险。
_EXT_BY_FORMAT = {"JPEG": "jpg", "PNG": "png", "WEBP": "webp"}
_CT_BY_FORMAT = {"JPEG": "image/jpeg", "PNG": "image/png", "WEBP": "image/webp"}

# 解压炸弹防线。上传接口的 2MB/5MB 上限约束的是「压缩后字节数」，对像素数毫无约束：
# 一张 6000×6000 的纯色 PNG 可压缩到约 116.8 KB（约 3322 字节/百万像素），解码后的
# 像素缓冲却是 108,000,000 字节（103 MB）—— 放大 903 倍，而这里的输出目标只有
# 200×200 / 1080×1080。也就是说「上限管的是输入，被吃掉的是输出」。
# Pillow 自身的 MAX_IMAGE_PIXELS 默认约 8948 万：超过只发 DecompressionBombWarning（不中断），
# 要到 2 倍即约 1.79 亿像素才抛错。按约 2.9 MB/百万像素折算，单张图在完全静默的前提下
# 就能吃掉约 256 MB（RGBA 约 341 MB），抛错阈值处约 512 MB。限流为 10 次/分钟/用户/IP，
# 键里带 user.id 与 ip，多账号多 IP 可并行放大，少量并发即可耗尽内存。
# 25M 像素（约 5000×5000，或 1080×23000 的长截图）已远超头像与反馈截图的实际需要
# （手机原图 4032×3024 = 12.2M），最坏解码内存约 75 MB（RGB）/ 100 MB（RGBA）。
MAX_UPLOAD_PIXELS = 25 * 1000 * 1000
# 防御纵深：把 Pillow 的全局阈值也压到同一水平，任何未经本模块尺寸校验就走到解码的路径
# 都会在 2 倍处直接抛 DecompressionBombError，而不是静默吃掉数百 MB。
Image.MAX_IMAGE_PIXELS = MAX_UPLOAD_PIXELS


def probe_image_size(file_bytes: bytes):
    """只读图片头拿声明尺寸，返回 (w, h)；无法识别时返回 None。

    Image.open 是惰性的：它只解析文件头，像素要等到 load()/thumbnail() 才真正解码，
    所以这里取尺寸的成本与图片体积无关，可以在解码之前就把炸弹挡掉。
    超过 2×MAX_UPLOAD_PIXELS 时 Image.open 自身就会抛 DecompressionBombError，
    一并落入下方的 except 返回 None，由调用方按「尺寸过大或文件损坏」拒绝。
    """
    try:
        with Image.open(io.BytesIO(file_bytes)) as im:
            return im.size
    except Exception as e:
        logger.warning(f"读取图片头失败，拒绝上传: {e}")
        return None


class COSService:
    def __init__(self):
        self.client = None
        self.bucket = settings.COS_BUCKET
        self.region = settings.COS_REGION
        self.cdn_domain = (settings.COS_CDN_DOMAIN or "").rstrip("/")
        self._init_client()

    def _init_client(self):
        try:
            if not (settings.COS_SECRET_ID and settings.COS_SECRET_KEY and self.bucket):
                logger.warning("腾讯云COS未完整配置，上传功能不可用")
                return
            from qcloud_cos import CosConfig, CosS3Client
            conf = CosConfig(
                Region=self.region,
                SecretId=settings.COS_SECRET_ID,
                SecretKey=settings.COS_SECRET_KEY,
                Scheme="https",
            )
            self.client = CosS3Client(conf)
        except Exception as e:
            logger.error(f"腾讯云COS初始化失败: {e}")
            self.client = None

    def _compress_image(self, file_bytes: bytes, max_size: tuple = None, quality: int = 85):
        """压缩图片（CPU密集，在线程池执行）。PIL 无法解析/压缩时返回 None，拒绝原样上传。
        返回 (压缩后字节, 真实输出格式)，供调用方推导扩展名与 ContentType。"""
        try:
            img = Image.open(io.BytesIO(file_bytes))
            img.verify()  # 校验图片完整性，损坏/伪造文件直接抛异常
            img = Image.open(io.BytesIO(file_bytes))  # verify 后需重新打开
            # 解码前的最后一道闸。upload.py 的 _validate 已按声明尺寸拦过一次，
            # 这里是防御纵深 —— 任何绕过上传校验直接调用压缩的路径同样不能解码炸弹。
            # 必须在 thumbnail() 之前：它内部会 load()，那一刻整幅原尺寸像素就进内存了。
            w, h = img.size
            if w <= 0 or h <= 0 or w * h > MAX_UPLOAD_PIXELS:
                logger.warning(f"图片声明尺寸超出上限，拒绝解码 size={img.size} "
                               f"pixels={w * h} 上限={MAX_UPLOAD_PIXELS}")
                return None
            if max_size:
                img.thumbnail(max_size, Image.LANCZOS)
            output = io.BytesIO()
            fmt = img.format if img.format in ("JPEG", "PNG", "WEBP") else "JPEG"
            if fmt == "JPEG":
                img = img.convert("RGB")
            img.save(output, format=fmt, quality=quality)
            return output.getvalue(), fmt
        except Exception as e:
            logger.error(f"图片压缩/校验失败，拒绝上传: {e}")
            return None

    def _upload_sync(self, key: str, data: bytes, content_type: str = "image/jpeg") -> bool:
        """同步上传（在线程池执行）"""
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Body=data,
                Key=key,
                ContentType=content_type,
            )
            return True
        except Exception as e:
            logger.error(f"COS上传失败 key={key}: {e}")
            return False

    def _public_url(self, key: str) -> str:
        if self.cdn_domain:
            return f"{self.cdn_domain}/{key}"
        return f"https://{self.bucket}.cos.{self.region}.myqcloud.com/{key}"

    async def _compress_and_upload(self, prefix: str, file_bytes: bytes, max_size: tuple) -> Optional[str]:
        """统一压缩+上传流程：扩展名与 ContentType 均取自真实格式"""
        if not self.client:
            return None
        packed = await asyncio.to_thread(self._compress_image, file_bytes, max_size, 85)
        if not packed:  # 压缩/校验失败拒绝上传
            return None
        compressed, fmt = packed
        ext = _EXT_BY_FORMAT.get(fmt, "jpg")
        key = f"{prefix}/{uuid.uuid4().hex}.{ext}"
        ok = await asyncio.to_thread(self._upload_sync, key, compressed, _CT_BY_FORMAT.get(fmt, "image/jpeg"))
        return self._public_url(key) if ok else None

    async def upload_avatar(self, file_bytes: bytes, filename: str) -> Optional[str]:
        """上传头像，压缩至200x200（filename 仅保留入参兼容性，不参与对象键生成）"""
        return await self._compress_and_upload("avatar", file_bytes, (200, 200))

    async def upload_feedback_image(self, file_bytes: bytes, filename: str) -> Optional[str]:
        """上传反馈截图，最大边1080px（filename 仅保留入参兼容性，不参与对象键生成）"""
        return await self._compress_and_upload("feedback", file_bytes, (1080, 1080))


cos_service = COSService()
oss_service = cos_service
