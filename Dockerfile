# 基础镜像默认走 Docker Hub（国外源）。抽成 ARG 后可在国内构建机上覆盖为镜像加速地址，例如：
#   docker compose build --build-arg BASE_IMAGE=docker.m.daocloud.io/library/python:3.12-slim
# 版本必须保持 3.12：requirements.txt 里 ephem/cryptography/Pillow 的预编译轮子按 cp312 选型。
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}
WORKDIR /app

# 包源可通过 build-arg 覆盖，默认使用国内镜像；海外构建示例：
#   docker compose build --build-arg APT_MIRROR=deb.debian.org \
#                        --build-arg PIP_INDEX_URL=https://pypi.org/simple
ARG APT_MIRROR=mirrors.aliyun.com
ARG PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple

# T1：容器时区固定为东八区，避免 datetime.now() 偏差 8 小时
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_INDEX_URL=${PIP_INDEX_URL} \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=Asia/Shanghai

# 系统依赖 + 时区数据（N8：创建非 root 用户，不以 root 运行）
# python:3.12-slim 基于 Debian 12(bookworm)，源写在 deb822 格式的
# /etc/apt/sources.list.d/debian.sources；更早的基础镜像用 /etc/apt/sources.list。
RUN set -eux; \
    for f in /etc/apt/sources.list.d/debian.sources /etc/apt/sources.list; do \
        if [ -f "$f" ]; then \
            sed -i "s|deb.debian.org|${APT_MIRROR}|g; s|security.debian.org|${APT_MIRROR}|g" "$f"; \
        fi; \
    done; \
    apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    default-libmysqlclient-dev \
    pkg-config \
    tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

COPY requirements.txt .
# 索引已由上面的 PIP_INDEX_URL 指向清华源，此处不再重复指定
RUN pip install --no-cache-dir -r requirements.txt

# P3（#66 镜像加固）：构建期依赖（gcc/MySQL 客户端头/pkg-config）在 pip 装完后即无用——
# requirements 里 cryptography/Pillow/ephem/pycryptodomex 均走 cp312 预编译轮子，aiomysql 为纯 Python，
# 运行期不需要编译器。留在运行镜像里等于给攻击者留下就地编译 exploit 的工具链，装完即 purge。
# 放在 pip install 之后：若真有包缺轮子需要现场编译，编译失败会先在本步之前暴露，不会静默带病上线。
RUN apt-get purge -y --auto-remove gcc default-libmysqlclient-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN mkdir -p /app/certs && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# L3（审计修复）：容器僵死/未监听端口时 docker 自动重启。
# 用 python urllib 探 /health，无需引入 curl（保持镜像精简）。
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3); sys.exit(0 if r.status==200 else 1)" || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
