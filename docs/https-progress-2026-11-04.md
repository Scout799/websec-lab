# 多域HTTPS与SameSite阶段验证记录

日期：2026-11-04。多域HTTPS与SameSite阶段验收完成：313项测试通过，Chrome/Edge正式96例通过，独立结果复核通过。项目使用Conda环境Websec，无新增Python依赖，新增本地Nginx网关。最终保留`https-samesite-lax`环境运行。

## 已完成改动

| 文件 | 改动 |
|---|---|
| `config/lab.https.yaml` | 独立HTTPS公共来源、回环后端端口15100–15400、独立数据库与可信单层代理开关 |
| `config/defense.yaml` | 增加Strict/Lax/None三个Secure会话配置，保留None无Secure的反例 |
| `src/websec_lab/https_lab.py` | 固定版本/哈希的Nginx安装、OpenSSL CA/SAN证书、当前用户信任导入、私钥权限、网关与后端生命周期、TLS/SNI健康检查、独立实验浏览器入口、重复停止处理 |
| `src/websec_lab/config.py` | 增加并校验trusted_proxy配置 |
| `src/websec_lab/services.py` | 仅HTTPS配置使用单层ProxyFix，恢复代理后的真实scheme和host |
| `src/websec_lab/victim/__init__.py` | HTTPS同源Referer策略，保留CSRF校验；只在local-only模式注册观察页 |
| `src/websec_lab/victim/cookie_probe.py` | 只读观察Cookie有无、登录态、Sec-Fetch-Site及真实协议，不返回Cookie值 |
| `src/websec_lab/templates/victim/cookie_probe.html` | 会话观察展示 |
| `src/websec_lab/attacker/__init__.py` | 增加iframe会话观察入口和演示后台内部映射 |
| `src/websec_lab/templates/attacker/cookie_lab.html` | 跨站及同站不同源实验入口，以及保留发起来源的顶层GET链接 |
| `src/websec_lab/attacker/demo.py` | HTTPS演示的状态/重置代理使用对应回环后端，避免操作系统未配置.test解析导致失败 |
| `src/websec_lab/partner/__init__.py` | 钱包组件使用配置中的HTTPS目标来源 |
| `src/websec_lab/auditor/origins.py` | same_site纳入scheme，区分HTTP与HTTPS |
| `src/websec_lab/experiments/samesite.py` | 96例矩阵编排；Cookie属性与阻断原因、服务端会话、几何检查与坐标点击、准确业务增量、顶层GET对照、逐例四张截图、JSON/CSV/Markdown输出 |
| `tests/test_https_lab.py` | 34项配置、路由、属性、站点关系、会话、CSRF及业务增量判定测试；包含异常单项状态变化的6例回归 |
| `scripts/https-lab.ps1` | 环境启停、状态、证书准备与实验浏览器包装命令 |
| `scripts/https_env_smoke.py` | 网关五域验证、私有控制路径、未知Host/SNI拒绝及真实浏览器TLS检查 |
| `scripts/https_click_diagnostic.py` | 同一浏览器下对比4种透明度，记录目标收到的可信鼠标事件与转账变化 |
| `scripts/verify_samesite_results.py` | 独立复核完整矩阵、会话、两项业务增量、浏览器阻断原因、逐例截图与JSON/CSV一致性 |
| `.gitignore` | 忽略本机私钥、浏览器配置、下载与运行数据目录.websec-local |
| `README.md`、`docs/https-samesite.md` | 入口、启动说明、信任安装及移除、预期矩阵与证据说明 |
| `PROJECT_TASKS.md`、`docs/status.md`、`docs/risks.md`、`docs/version-manifest.md` | HTTPS里程碑、实际部署方式、站点关系、浏览器及网关版本同步 |

## 已有实测

| 检查 | 结果 |
|---|---|
| 最新全量pytest | 313通过，0失败、0错误、0跳过，99.64秒 |
| Ruff | 全通过 |
| Black | 86个Python文件符合格式 |
| 五个域名TLS链、主机名/SNI、健康检查及路由 | 全部通过，均返回200 |
| HTTPS侧访问私有控制路径 | 五域均返回404 |
| 未配置的HTTP Host | 返回421 |
| 不在SAN中的SNI域名 | TLS主机名校验拒绝 |
| 停止、冷启动、重复启动、重复停止 | 7步启停检查通过；重复启动PID不变，停止后五端口释放，最终默认Lax配置运行 |
| 私钥权限 | 限当前账号；Git忽略整个本机运行目录 |
| Chrome 156.0.8078.80 / Edge 156.0.4314.58默认TLS校验 | 均通过；未忽略证书错误，页面处于安全上下文 |
| Chrome单轮预跑 | 16/16通过，包括iframe和顶层GET两类会话观察 |
| Chrome/Edge正式矩阵 | 96/96通过，0失败，580.55秒；每个组合两种浏览器各3次 |
| 独立证据复核 | 96例数据、精确业务增量、阻断原因、JSON/CSV和384张截图全部通过 |

证据：[全量测试XML](../artifacts/verification/2026-11-04-https/pytest.xml)、[HTTPS及浏览器环境检查JSON](../artifacts/verification/2026-11-04-https/environment.json)、[7步启停记录](../artifacts/verification/2026-11-04-https/lifecycle.json)。

五个域名：victim.test、attacker.test、same.victim.test、partner.test、audit.test，统一HTTPS端口8443。网关与后端均仅绑定127.0.0.1，未修改系统hosts，域名映射限专用浏览器进程。

## 证书与运行隔离

用户已确认安装 **WebSec Local Lab CA**，证书仅导入当前用户Root信任库。初始化重复执行成功，没有生成另一张CA。CA证书SHA-256：

`976e50bc141b0bb8728e19fa2dc6ac81f98489a8682698083195b22e1edbcf68`

CA标识指纹（仅用于证书库查找/移除）：

`5CF6C24ED556FA2283DEC7AC0FECB16AA83ED102`

网关Nginx 1.30.6，官方压缩包SHA-256：`c6ee35edb0a861063323f709192ae50d1eefaf2ea7d00678bd2b22d8542dc61e`。证书使用Websec环境内的OpenSSL 3.5.9生成，CA有效期365天、服务器证书90天。SAN覆盖五个域名。私钥ACL核实仅当前账号SCOUTZZ\Scout可访问，Git忽略检查通过。

每个实验使用全新临时浏览器配置，第三方Cookie允许/阻止由该配置与CDP明确设置，实验结束关闭浏览器并清除临时配置。Cookie观察页只返回有无、登录态与属性，不导出会话Cookie值。HTTPS数据库单独保存在`.websec-local/https.sqlite3`，原HTTP数据库保留。

## 预跑中修正的问题

1. **证书信任**：系统确认完成后，改用当前用户证书库API完成导入，并再次在两种浏览器正常TLS校验下验证；未添加忽略证书错误选项。
2. **页面等待**：初次预跑16例在攻击页等待`networkidle`超时，Cookie观察已完成，但这些例子全部记失败。改为等待页面加载、对齐完成和目标控件，保留首次原始输出于`artifacts/samesite-https-preflight`。
3. **跨站透明度**：第二次预跑15/16通过；`None+Secure`跨站允许Cookie时登录态存在，透明度0却无转账。对照诊断确认Chrome中0无鼠标事件，0.01、0.35、1均收到`isTrusted=true`事件并转账。正式实验固定0.01并记录参数、点击前截图、点击点及目标几何；未关闭站点隔离或浏览器防御。该现象的浏览器内部成因未作推断。
4. **点击与判定**：脚本检查坐标命中透明iframe，并在已登录时验证点位于目标按钮；布局稳定后只点击一次。成功需新增1笔转账且余额减少123分；未成功的预期需两项均为0，异常单项变化不算通过。结果另由独立脚本复核。
5. **Lax/Strict区分**：追加从诱导页点击真实链接的顶层GET对照；攻击段完成后才进行，避免对前面的会话和业务观察产生干扰。

## 正式矩阵与证据

矩阵为4种Cookie配置×2种来源关系×2种第三方Cookie设置×2种浏览器×3次重复，共96例。每例包含iframe观察、一次坐标点击与顶层GET观察；不是96种不同配置，也不代表96次攻击都成功。

正式运行96例全部通过，独立复核96例通过。42例新增恰好1笔转账且余额减少123分，54例两项均不变。结果如下：

| Cookie配置 | 同站iframe（允许或阻止第三方Cookie） | 跨站iframe：允许第三方Cookie | 跨站iframe：阻止第三方Cookie | 跨站顶层GET导航 |
|---|---|---|---|---|
| Strict + Secure | 携带会话，模拟转账触发 | 不携带，不触发 | 不携带，不触发 | 不携带会话 |
| Lax + Secure | 携带会话，模拟转账触发 | 不携带，不触发 | 不携带，不触发 | 携带会话 |
| None + Secure | 携带会话，模拟转账触发 | 携带会话，模拟转账触发 | 不携带，不触发 | 携带会话 |
| None无Secure | 浏览器拒绝保存Cookie，未登录，不触发 | 同左 | 同左 | 无有效会话 |

浏览器阻断证据区分了`SchemefulSameSiteStrict`、`SchemefulSameSiteLax`、`UserPreferences`和`SameSiteNoneInsecure`。本表中“未触发”依据服务器转账增量与余额差，不依据iframe加载事件。所有iframe观察的`Sec-Fetch-Site`均与预定same-site/cross-site关系一致。顶层GET观察在攻击完成后从诱导页点击真实链接取得。

因此，SameSite在本实验中限制跨站iframe的会话发送；同站不同源iframe仍可使用会话。`None+Secure`允许跨站会话时，第三方Cookie隐私策略还能额外阻断。Lax与Strict的差别通过顶层安全方法导航得到验证。

原始证据：

- [汇总](../artifacts/samesite-https/summary.md)、[元数据](../artifacts/samesite-https/summary.json)
- [CSV明细](../artifacts/samesite-https/results.csv)、[JSON原始记录](../artifacts/samesite-https/results.json)
- [独立复核](../artifacts/samesite-https/verification.json)
- [透明度诊断](../artifacts/verification/2026-11-04-https/click-diagnostic/results.json)

## 使用与下一步范围

完整启停、切换配置和独立浏览器入口见[部署说明](https-samesite.md)。该环境通过浏览器进程的域名映射运行，未修改系统hosts。日常浏览器不能直接依靠该映射解析`.test`，需要使用项目的`browser`命令。

本轮验收覆盖原生HTTPS网关、四服务入口和SameSite专用矩阵。通用审计CLI的Python侧域名/CA传输、HTTPS探针来源接入、全部防御profile的HTTPS复测，以及Docker编排仍列后续任务。本轮不改写历史M9实验结论，不声称已验证Firefox。
