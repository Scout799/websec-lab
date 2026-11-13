# 多域 HTTPS 与 SameSite 实验

本环境使用本机 Nginx、OpenSSL 和现有 Websec Python 环境，不依赖 Docker。

## 域名、来源与站点

| 地址 | 后端 | 用途 |
|---|---|---|
| `https://victim.test:8443` | `127.0.0.1:15100` | 目标站，登录与模拟转账 |
| `https://attacker.test:8443` | `127.0.0.1:15200` | 跨站攻击来源 |
| `https://same.victim.test:8443` | 同一攻击后端 | 同站不同源的对照来源 |
| `https://partner.test:8443` | `127.0.0.1:15300` | 合作方嵌入组件 |
| `https://audit.test:8443` | `127.0.0.1:15400` | 审计服务入口 |

所有监听均限回环地址。`victim.test` 与 `same.victim.test` 的 schemeful site 均为 `https://victim.test`，但 origin 不同；`attacker.test` 与目标跨站。Cookie 为 host-only，未设置 Domain，实际由浏览器判断是否向目标 iframe 请求携带。

## 初始化与信任

在工程根目录执行：

```powershell
conda activate Websec
python -m websec_lab.https_lab setup --trust
```

脚本从 Nginx 官方 HTTPS 地址下载固定版本 1.30.6，校验内置 SHA-256。OpenSSL 生成有效期 365 天的本地CA与有效期90天的服务器证书，SAN覆盖五个域名。私钥目录移除继承权限，仅授予当前账号访问，整个 `.websec-local` 被 Git 忽略。

`--trust` 通过Windows证书库API将 **WebSec Local Lab CA** 导入**当前用户**的Root证书库。本机已获用户确认并完成安装。证书未信任时，浏览器实验应报 `ERR_CERT_AUTHORITY_INVALID`，不能通过忽略证书错误来取得正式结果。

CA公钥证书、指纹与运行信息保存在 `.websec-local/certs/root-ca.crt`、`.websec-local/setup.json`。移除信任时，核对该文件的 `root_thumbprint`，仅删除这张证书：

```powershell
certutil -user -delstore Root <本实验CA的root_thumbprint>
```

不要将CA私钥分享给其他人或拷贝到仓库；其他机器应自行生成并信任各自的CA。

## 启停与访问

```powershell
python -m websec_lab.https_lab start --profile https-samesite-lax
python -m websec_lab.https_lab status
python -m websec_lab.https_lab browser --browser chrome
python -m websec_lab.https_lab stop
```

也可执行 `scripts/https-lab.ps1 -Action start` 等包装命令。

当前账号无管理员权限，因此未修改系统hosts。`browser` 命令启动独立配置的Chrome/Edge，通过该进程的 `--host-resolver-rules` 将实验 `.test` 域名映射到回环地址，避免外部代理；**没有** `--ignore-certificate-errors` 或 `--disable-web-security`。直接在日常浏览器输入这些地址，若未另外配置hosts，可能无法解析。

手动演示先在目标站使用虚构账号 `alice / alice-lab` 登录，再查看两个诱导站点的 `/cookie-lab` 页面。透明覆盖使用 `/scenarios/overlay/run?opacity=0.01`；等待页面对齐稳定后点击诱导按钮。调试时可用 `?debug=1&opacity=0.35` 查看真实目标位置。

手动浏览器使用专属配置 `.websec-local/manual-browser/<channel>`，首次创建时允许第三方Cookie，以便看清SameSite差异。需要测试额外隐私拦截时，只修改该实验浏览器的第三方Cookie设置。自动矩阵每例另建全新临时配置，不复用手动浏览器或日常浏览器数据。

切换配置前先停止已有实例：

```powershell
python -m websec_lab.https_lab stop
python -m websec_lab.https_lab start --profile https-samesite-none
```

原生HTTP配置 `config/lab.yaml` 和端口5100–5400仍保留。HTTPS配置 `config/lab.https.yaml` 使用独立数据库 `.websec-local/https.sqlite3`。只有HTTPS配置启用单层可信代理头；登录CSRF检查仍开启，通过同源Referrer策略保持正常登录。

## 自动实验

```powershell
# 先停止手动演示实例，矩阵会管理自己的四个后端和Nginx。
python -m websec_lab.https_lab stop
python -m websec_lab.experiments.samesite --browser both --repeats 3 --out artifacts/samesite-https
python scripts/verify_samesite_results.py --out artifacts/samesite-https --repeats 3
python -m websec_lab.https_lab start
```

矩阵：4种Cookie配置 × 2种来源关系 × 2种第三方Cookie设置 × 2种浏览器 × 3次重复，共96例。

| 配置 | 同站iframe | 跨站iframe：允许第三方Cookie | 跨站iframe：阻止第三方Cookie |
|---|---|---|---|
| Strict + Secure | 预期携带登录态 | 预期不携带 | 预期不携带 |
| Lax + Secure | 预期携带登录态 | 预期不携带 | 预期不携带 |
| None + Secure | 预期携带登录态 | 预期携带 | 预期不携带 |
| None但无Secure | 预期浏览器拒绝保存Cookie，无法建立登录态 | 同左 | 同左 |

这是预期表，不应代替实际结果。自动实验需要真实浏览器、证书信任与空闲端口。第三方Cookie设置通过临时浏览器Preferences与CDP `Network.setCookieControls` 明确控制，记录阻断原因与版本，不能把额外隐私拦截等同于SameSite机制。

每例记录：

1. 浏览器保留的Cookie属性，TLS安全上下文与版本；
2. CDP关联Cookie的阻断原因与不安全Cookie拒绝原因（不导出Cookie值）；
3. 服务器实际收到的Cookie有无、登录态与 `Sec-Fetch-Site`；
4. 诱导按钮位置的真实坐标点击；
5. 服务器转账记录增量与余额差，判断是否确有敏感操作；
6. 观察页和点击后截图，以及逐例JSON、CSV和汇总。

每例还从诱导页点击真实链接，执行顶层GET导航，记录目标站收到的会话。在跨站导航对照中，Strict不携带登录态，Lax和None+Secure携带登录态；设置第三方Cookie阻止不应阻止目标成为顶层后的正常会话。该对照在攻击状态检查之后执行，避免改变前一段iframe实验。

攻击判定要求新增恰好1笔转账且余额减少123分；未触发操作的例子要求两项均不变。脚本检查诱导按钮坐标首先命中`victim-frame`，有登录态时检查该点位于目标按钮范围内，仍由`page.mouse.click`发送坐标点击。

本机Chrome156的透明度诊断显示：跨站iframe在`opacity=0`时未收到可信鼠标点击，`0.01`、`0.35`与`1`时均收到可信事件并新增1笔转账。正式实验统一固定`opacity=0.01`，保存点击前截图、几何位置与参数，避免将该差异混入Cookie判定。页面就绪使用加载完成、对齐提示和目标控件，未再使用遥测请求可能干扰的`networkidle`等待。

SameSite限制会话发送，不必阻止iframe本身加载。真实点击结果还受XFO/CSP、CSRF和浏览器隐私设置等因素影响。本矩阵的三个HTTPS主配置不设置框架限制，以隔离Cookie效果；未关闭CSRF检查。

## 阶段验证与后续接入

五个域名的CA链、主机名/SNI与HTTPS健康检查均通过，Chrome和Edge均在正常证书校验下访问成功。全量pytest为313项通过；Chrome预跑16例、正式矩阵96例均全部通过。独立复核确认96例业务增量、阻断原因、JSON/CSV与384张截图一致。正式结果见[实验汇总](../artifacts/samesite-https/summary.md)，逐项改动与验收见[阶段记录](https-progress-2026-11-04.md)。

上述313项为2026-11-04阶段记录。2026-11-07收尾已接通通用`analyze`、`audit`、`audit-report`的HTTPS传输、主机名/SNI校验和显式探针来源；新增最终954例主实验及对照，三浏览器完成，见[最终状态](status.md)。96例专项仍以自己的问题和分母单独报告。

## 技术依据

- [MDN：Set-Cookie及SameSite语义](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- [Chrome DevTools Protocol：Cookie控制与阻断原因](https://chromedevtools.github.io/devtools-protocol/tot/Network/)
- [Nginx：Windows运行与进程管理](https://nginx.org/en/docs/windows.html)
- [Chromium：近期移动iframe的输入干预说明](https://groups.google.com/a/chromium.org/g/blink-dev/c/58JoaBbCao0)；本实验保留浏览器干预，并在布局稳定后点击。透明度为零的具体内部原因未据此认定。
