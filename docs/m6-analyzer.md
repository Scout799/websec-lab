# M6 静态策略分析器说明

更新时间：2026-11-04（审计判定修复）

## 组成

| 模块 | 职责 |
|---|---|
| [auditor/fetch.py](../src/websec_lab/auditor/fetch.py) | 抓取本地目标、手工跟随并记录重定向链；只允许回环与 `*.test` 主机（威胁模型边界） |
| [auditor/headers.py](../src/websec_lab/auditor/headers.py) | 响应头归一化：名称小写、多值保序（重复头是重要错误类别）、CSP/XFO 逗号拆分 |
| [auditor/origins.py](../src/websec_lab/auditor/origins.py) | origin 解析与 CSP 来源表达式匹配（scheme/host/port/通配符；`*.test` 匹配子域；路径按 CSP3 忽略） |
| [auditor/parsers.py](../src/websec_lab/auditor/parsers.py) | XFO 解析（DENY/SAMEORIGIN/ALLOW-FROM 废弃/非法值/重复）、CSP frame-ancestors 解析（多策略交集、Report-Only、畸形指令）、Set-Cookie 属性解析 |
| [auditor/rules.py](../src/websec_lab/auditor/rules.py) | 规则库 WS001–WS012（等级 + 修复建议）与风险评分（可加权重 + contributions 证据明细） |
| [auditor/analyzer.py](../src/websec_lab/auditor/analyzer.py) | 编排：多级祖先判定（SAMEORIGIN 全链同源；frame-ancestors 逐祖先逐策略）、XFO/CSP 冲突识别、来源—权限矩阵 |
| [auditor/routes.py](../src/websec_lab/auditor/routes.py) | 服务 API：抓取式 `GET /api/analyze`、离线式 `POST /api/analyze`、`GET /api/rules` |

## 判定语义

- **XFO**：`DENY` 全拒；`SAMEORIGIN` 要求祖先链全部与目标同源；`ALLOW-FROM` 与非法值被现代浏览器忽略（按无保护处理并触发规则）；重复头取第一个值并标记歧义。
- **CSP**：多个强制策略按**交集**执行——每个策略都必须放行每一个祖先；Report-Only 不参与阻断；`'none'` 与其他来源混用会触发 WS011，但浏览器忽略其中的 `'none'`，继续匹配其他来源。
- **两套机制并存**：生效的 `frame-ancestors` 覆盖 XFO；只有 Report-Only 或 CSP 没有 `frame-ancestors` 时，XFO 仍参与执行。两套配置的语义分歧继续触发 WS005，不能把冲突时的实际行为错误建模为两者交集。
- **来源与重定向**：`'self'` 按最终响应 URL 的来源判断；host-source 省略端口时仅匹配默认端口，显式 `:*` 才匹配任意端口。

合并报告保留请求祖先链的 `static` 结果，另外生成 `probe_static`，使用浏览器实际来源和文档响应重新分析。`consistency` 只比较后者与动态结果；缺少浏览器响应或出现运行错误时，`agree=null`。

## 使用

```powershell
# CLI：对本地目标做静态分析
websec-lab analyze http://127.0.0.1:5100/lab/quick-transfer --ancestor http://127.0.0.1:5200
websec-lab analyze http://127.0.0.1:5100/login --json   # 完整 JSON

# 服务 API（auditor 运行于 :5400）
curl "http://127.0.0.1:5400/api/analyze?url=http://127.0.0.1:5100/login&ancestor=http://127.0.0.1:5200"
curl http://127.0.0.1:5400/api/rules

# 离线模式：分析已记录的响应头（语料/回放用）
curl -X POST http://127.0.0.1:5400/api/analyze -H "Content-Type: application/json" ^
  -d "{\"url\":\"http://victim.test/x\",\"headers\":{\"x-frame-options\":[\"DENY\"]},\"ancestors\":[\"http://attacker.test:5200\"]}"
```

## 规则库

| 编号 | 等级 | 标题 |
|---|---|---|
| WS001 | high | 无任何嵌入防护 |
| WS002 | medium | X-Frame-Options 值非法 |
| WS003 | low | 重复的 X-Frame-Options 头 |
| WS004 | medium | 使用已废弃的 ALLOW-FROM |
| WS005 | medium | XFO 与 CSP frame-ancestors 语义冲突 |
| WS006 | info | 存在多个 CSP 策略（交集语义） |
| WS007 | high | frame-ancestors 使用通配符 |
| WS008 | medium | 仅 Report-Only 无强制策略 |
| WS009 | medium | SameSite=None 且缺少 Secure |
| WS010 | low | 会话 Cookie 缺少 HttpOnly/Secure |
| WS011 | info | frame-ancestors 配置畸形 |
| WS012 | info | XFO 与 CSP 配置一致（健康） |

## 验证结果

本节后续数字为历史基线。2026-11-04 修复后的测试、真实浏览器回归与证据见 [修复验证记录](audit-fix-2026-11-04.md)。旧的“100%一致”不能作为修复后正式实验数据。

- **语料库**：`tests/corpus/policy_corpus.yaml` 19 例（正常/冲突/畸形/多级/Cookie），覆盖全部 12 条规则，参数化断言决策与规则集合。
- **静态 vs 动态一致性**（`scripts/m6_smoke.py`）：对 13 个 M5 防御 profile 起真实 victim，抓取分析得出的嵌入判定与 m5_smoke 真实浏览器攻防结果 **100% 一致**——静态 allowed 的 4 个 profile（none、ALLOW-FROM 忽略、通配白名单、Report-Only）恰为动态实验中攻击成功的 4 个，其余全部双向 blocked。这一致性将作为 M9 指标 T0910（静态预测与动态结果一致率）的基线。
- 回归：pytest 190 项、Ruff/Black、M3/M5 烟雾全部通过。

## 已知边界

- 站点（eTLD+1）计算用"最后两段"近似，未引入完整 Public Suffix List（实验域均为 `*.test`，足够）；
- XFO 重复头的浏览器行为存在差异，分析器取第一个值并显式标记歧义（WS003）；
- T0611（与 framing-control-analytics 对比）待上游工具可获取后补做。
