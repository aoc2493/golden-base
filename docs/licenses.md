# 第三方许可证维护

生产依赖的许可证清单保存在仓库根目录
[`THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md)。

该文件覆盖 `requirements.txt` 的直接和间接 Python 依赖，不包含测试、静态检查、
漏洞扫描等开发工具。

## 重新生成

在与部署目标相同的平台上，使用仅安装生产依赖和许可证扫描工具的独立环境执行：

```bash
python -m pip install -r requirements.txt
python -m pip install pip-licenses==5.5.5
python scripts/generate_third_party_licenses.py
```

脚本使用 `pip-licenses` 读取已安装包的元数据、许可证文件和 NOTICE。若某个包没有
提供许可证原文，脚本会失败，要求维护者从该包的上游仓库核对后补充例外，而不会生成
不完整的清单。

依赖可能按操作系统安装不同组件。例如 `uvicorn[standard]` 在 Linux 上安装
`uvloop`，在 Windows 上安装 `colorama`。用于 Docker 发行时应在 Linux 环境中重新
生成清单；脚本检测到 pytest、Ruff、Mypy 等开发工具时会直接拒绝运行。

升级 `requirements.txt` 后必须重新生成并检查差异。

## 发布注意事项

- GitHub 源码分发以根目录 [`LICENSE`](../LICENSE) 声明项目自身授权。
- Docker 镜像或离线安装包还应保留 Python、Debian 基础镜像及系统软件包的许可证。
- Apache-2.0 依赖的 `NOTICE` 必须随发行物保留。
- 许可证字段来自包元数据，发现异常时应以对应上游仓库的许可证原文为准。
