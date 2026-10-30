"""模块导入冒烟测试。

导入测试用于捕获结构调整（移动模型、修改 import 路径）造成的模块引用断裂；
仅靠业务用例可能全部通过，直到线上才出现 ImportError。

判定原则（关键）：
  · 缺失的是「项目内模块」（app.*）→ 判定为**失败**：这是真正的引用断裂。
  · 缺失的是「第三方依赖」      → 跳过：本地环境没装全，不是代码问题。
这样既能捕获重构引入的断链，又不会因为环境缺包而误报。
"""
import importlib
import pathlib


APP_ROOT = pathlib.Path(__file__).resolve().parents[1] / "app"


def _iter_module_names():
    for base in ("core", "plugins"):
        root = APP_ROOT / base
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            rel = path.relative_to(APP_ROOT).with_suffix("")
            parts = list(rel.parts)
            if parts[-1] == "__init__":
                parts = parts[:-1]
            if not parts:
                continue
            yield "app." + ".".join(parts)


def test_all_modules_import_cleanly():
    failed = []
    skipped = []

    for module_name in _iter_module_names():
        try:
            importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            missing = getattr(exc, "name", "") or ""
            if missing.startswith("app."):
                failed.append(f"{module_name} -> 引用了不存在的项目模块 {missing}")
            else:
                skipped.append(f"{module_name} (缺第三方依赖 {missing})")
        except Exception as exc:  # 其它导入期异常同样是真问题
            failed.append(f"{module_name} -> {type(exc).__name__}: {exc}")

    if skipped:
        print("\n因缺少第三方依赖而跳过的模块:")
        for item in skipped:
            print("  -", item)

    assert not failed, "存在引用断裂或导入期异常:\n" + "\n".join(failed)
