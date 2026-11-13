# 版本与验收清单

2026-11-07，工程1.0.0。发布以文件SHA-256标识，不表示已创建Git标签。

| 组件 | 验证值 |
| --- | --- |
| Windows | Windows-11-10.0.26100-SP0 |
| Python | 3.12.15 | packaged by Anaconda, Inc. | (main, Oct  1 2026, 20:14:50) [MSC v.1942 64 bit (AMD64)] |
| Flask | 3.1.3 |
| SQLAlchemy | 2.1.6 |
| playwright | 1.64.0 |
| requests | 2.34.2 |
| pytest | 9.1.1 |
| ruff | 0.17.1 |
| black | 26.10.1 |

浏览器：Chrome156.0.8078.80，Edge156.0.4314.58，Playwright Firefox157.0。Windows Nginx1.30.6；Linux实际网关版本见linux-ca-after.json，Chromium版本见Linux烟雾JSON。Python完整依赖见requirements.lock。

本地验收结果见status.md。CI已配置，远程运行未执行；报告/PPT制作工具不是服务启动依赖。
