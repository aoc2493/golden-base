"""
微信公众号(服务号)网页授权工具
- 登录主路径用 snsapi_base 静默授权：用户无感知、不弹授权框，只拿 openid（不采集昵称头像）
- 头像/昵称同步用 snsapi_userinfo 显式授权（用户点「同步微信头像」才发起，弹确认框），
  换取 access_token 后调 /sns/userinfo 取 nickname/headimgurl（个保法：单独同意、按需采集）
- 流程：前端跳转 build_authorize_url -> 微信回跳带 code -> code2session 用 code 换 openid/unionid
- 文档：https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html
"""
import logging
from typing import Optional
from urllib.parse import quote
import httpx
from app.config import settings

logger = logging.getLogger(__name__)

# 公众号网页授权入口（open 形式，snsapi_base 静默）
_AUTHORIZE_URL = "https://open.weixin.qq.com/connect/oauth2/authorize"
# code 换网页授权 access_token / openid
_CODE2SESSION_URL = "https://api.weixin.qq.com/sns/oauth2/access_token"
# snsapi_userinfo 授权后拉取用户资料（昵称/头像）
_USERINFO_URL = "https://api.weixin.qq.com/sns/userinfo"


def _oa_app_id() -> str:
    return settings.WECHAT_OA_APP_ID or settings.WECHAT_APP_ID


def oauth_configured() -> bool:
    """是否已配置服务号网页授权"""
    return bool(_oa_app_id() and settings.WECHAT_OA_APP_SECRET)


def redirect_uri() -> str:
    """授权回跳地址：优先显式配置，否则用 H5_BASE_URL/index.html"""
    if settings.WECHAT_OAUTH_REDIRECT:
        return settings.WECHAT_OAUTH_REDIRECT
    base = (settings.H5_BASE_URL or "").rstrip("/")
    return f"{base}/index.html" if base else ""


def build_authorize_url(state: str = "", scope: str = "snsapi_base") -> Optional[str]:
    """
    拼接公众号授权链接
    :param state: 透传参数（推荐 base64 的 {ref, path}），微信原样回传，用于邀请绑定与回跳原页面
    :param scope: snsapi_base=静默仅 openid（登录主路径）；snsapi_userinfo=显式授权可取昵称头像
    """
    appid = _oa_app_id()
    redir = redirect_uri()
    if not appid or not redir:
        logger.warning("微信网页授权未配置 AppID/回跳域名，无法生成授权链接")
        return None
    # 不在此处截断：sign_state 已保证整串（payload + "." + 24位签名）不超过微信的
    # 128 字节上限。原来的 (state or "STATE")[:128] 砍掉的正是签名尾部，
    # 导致回跳后验签必然失败、微信内无法登录。
    state = state or "STATE"
    if len(state) > 128:
        logger.warning(f"授权 state 长度 {len(state)} 超出微信 128 字节上限，将被微信侧截断")
    return (
        f"{_AUTHORIZE_URL}?appid={appid}"
        f"&redirect_uri={quote(redir, safe='')}"
        f"&response_type=code&scope={scope}&state={quote(state)}#wechat_redirect"
    )


async def code2session(code: str) -> Optional[dict]:
    """
    用授权 code 换取 openid / unionid
    返回 {openid, unionid(可能为空), access_token, expires_in, refresh_token, scope}
    """
    appid = _oa_app_id()
    if not appid or not settings.WECHAT_OA_APP_SECRET:
        logger.warning("微信网页授权未配置 AppID/AppSecret")
        return None
    params = {
        "appid": appid,
        "secret": settings.WECHAT_OA_APP_SECRET,
        "code": code,
        "grant_type": "authorization_code",
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(_CODE2SESSION_URL, params=params)
            data = resp.json()
    except Exception as e:
        logger.error(f"微信code2session请求异常: {e}")
        return None
    if data.get("errcode"):
        # 只打错误码字段：整包 data 在“有 access_token 但没 openid”等异常分支里
        # 会带上公众号级凭证，写进日志（还会被日志采集外传）等于泄露。
        logger.error(f"微信code2session失败: errcode={data.get('errcode')} errmsg={data.get('errmsg')}")
        return None
    if not data.get("openid"):
        logger.error(f"微信code2session未返回openid: scope={data.get('scope')}")
        return None
    # 只回传业务真正要用的字段：snsapi_base 静默授权拿到的 access_token 仅能换 openid，
    # 全仓无任何调用方使用，留在返回值里只会在别处被误打进日志或误存进库。
    # snsapi_userinfo 流程（头像/昵称同步）需要 access_token + scope 校验，按需带出。
    result = {
        "openid": data.get("openid"),
        "unionid": data.get("unionid"),
        "scope": data.get("scope"),
    }
    if (data.get("scope") or "").find("snsapi_userinfo") >= 0:
        result["access_token"] = data.get("access_token")
    return result


async def fetch_userinfo(access_token: str, openid: str) -> Optional[dict]:
    """snsapi_userinfo 授权后拉取昵称/头像。
    仅在用户显式点击「同步微信头像昵称」并完成 userinfo 授权后调用（单独同意、按需采集）。
    返回 {nickname, headimgurl}；失败返回 None（调用方给出可恢复提示）。"""
    if not access_token or not openid:
        return None
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(_USERINFO_URL, params={
                "access_token": access_token, "openid": openid, "lang": "zh_CN"})
            data = resp.json()
    except Exception as e:
        logger.error(f"微信userinfo请求异常: {e}")
        return None
    if data.get("errcode"):
        # 只打错误码：整包可能含凭证字段，不外泄进日志
        logger.error(f"微信userinfo失败: errcode={data.get('errcode')} errmsg={data.get('errmsg')}")
        return None
    if not data.get("openid"):
        return None
    return {
        "openid": data.get("openid"),
        "unionid": data.get("unionid"),
        "nickname": data.get("nickname"),
        "headimgurl": data.get("headimgurl"),
    }
