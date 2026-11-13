# 开发约定

## 环境

统一使用 Conda 环境 `Websec` 和 Python 3.12。所有命令从仓库根目录执行。

```powershell
conda activate Websec
python --version
```

## 安装

```powershell
python -m pip install -e ".[dev]"
```

## 提交前检查

```powershell
ruff check .
black --check .
pytest --cov=websec_lab
```

## 代码原则

- 服务必须通过应用工厂创建，避免导入时启动服务器；
- 配置必须来自 YAML 或环境变量，不在业务代码中硬编码域名；
- 测试不能依赖执行顺序；
- 产生状态的测试必须在结束后清理；
- 攻击成功必须通过服务端状态确认，不能只依靠截图判断；
- 每个风险结论必须关联可检查的证据；
- 安全实验功能只允许在 `local_only: true` 的配置下运行。

## 分支与提交建议

- `main`：始终保持可运行；
- 功能分支：`feature/<task-id>-short-name`；
- 修复分支：`fix/<task-id>-short-name`；
- 提交信息包含任务编号，例如 `T0201: add local authentication skeleton`。

