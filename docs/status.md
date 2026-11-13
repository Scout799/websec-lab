# 最终工程状态

更新：2026-11-07，版本 1.0.0。本次核心工程、正式实验、复现验收和答辩交付已完成。

| 项目 | 验收结果 | 证据 |
| --- | --- | --- |
| Windows 全量 pytest | 327 项，失败 0、错误 0、跳过 0 | artifacts/finalization/pytest-final.xml |
| Linux 非浏览器测试 | 313 项，失败 0、错误 0、跳过 0 | artifacts/finalization/linux-pytest.xml |
| Ruff / Black | 通过 | artifacts/finalization/quality.log |
| 正式主实验与对照 | 954 个唯一用例，全部通过独立复核 | artifacts/final-results/verification.json |
| SameSite 跨站专项 | 96 个用例、384 张截图，复核通过 | artifacts/samesite-https/verification.json |
| 手动场景 UI | 三浏览器默认参数与缩放共 12 例通过 | artifacts/finalization/manual-ui/summary.json |
| 系统演练 | Chrome / Firefox 两轮通过 | artifacts/finalization/rehearsals/summary.json |
| 清洁 Windows 环境 | 精确依赖、wheel 安装与四服务页面通过 | artifacts/finalization/clean-install-smoke.json |
| Linux Docker | 健康、五域 TLS、真实 Chromium、诱导阻断、合法组件通过 | artifacts/finalization/linux-smoke-cookie-fixed.log |
| Linux 从零运行状态 | 新建卷生成新 CA，再次通过烟雾 | artifacts/finalization/linux-from-zero.log |
| 报告与 PPT | 12 页 PDF、Markdown/HTML、20 页可编辑 PPT，渲染检查通过 | deliverables/ |
| 视频与小组材料 | 1280×900，约 97 秒；讲稿、问答、操作手册与图表 | deliverables/ |

正式矩阵覆盖28配置、3种浏览器和3次重复，含837个iframe攻击、54个窗口路径、36个合法组件检查、27个正常交互。执行通过表示流程和证据成立，不表示攻击成功。原始首轮945例、18例判定修复复测、9例支付对照、54例HTTPS来源修正复测均保留，最终按case_id合并。

双通道融合标记657/891个攻击尝试，覆盖产生业务变化的攻击414/459个，正常对照误报10/27。合法支付与窗口无信号路径保留在结果中。静态/动态一致873/873仅对应具有双方结论的嵌入检查。

Windows最终恢复https-samesite-lax手动环境，五域均200。更换演示配置先stop再start。发布包附SHA-256文件清单，排除本机私钥、数据库、浏览器配置和验证虚拟磁盘。

人工答辩彩排与姓名确认由小组进行；自动系统演练没有代替人工作答。CI已配置但未发布仓库或触发远程执行。历史Backlog中的拖拽攻击、上游解析器对比、Web控制台及历史回放属于未纳入本次交付的可选扩展，不计入已完成成果。

材料入口：[最终报告](../deliverables/点击劫持项目最终报告.md)、[答辩PPT](../deliverables/点击劫持项目答辩.pptx)、[小组手册](../deliverables/三人汇报与操作手册.md)、[详细改动记录](finalization-ledger.md)。
