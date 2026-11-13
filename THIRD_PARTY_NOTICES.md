# 第三方软件与署名

本工程自有源码采用 MIT 许可证。依赖保留各自许可证，工程 MIT 声明不改变依赖授权。

包名、版本、网址、许可证元数据及可读取的许可证正文见 `artifacts/finalization/dependency-licenses.json`。该清单覆盖作者环境，包含文档检查包；实际运行、开发及报告依赖固定在 requirements.lock。PyMuPDF 属于可选 QA 依赖，不是实验服务器的启动依赖。

以下程序不作为二进制附带交付：

| 软件 | 用途 | 来源与许可证入口 |
| --- | --- | --- |
| Python / Conda | 运行时和隔离环境 | https://www.python.org/psf/license/ ，https://docs.conda.io/ |
| Nginx | TLS 网关 | https://nginx.org/en/LICENSE |
| OpenSSL | 证书 | https://openssl-library.org/source/license/ |
| Playwright | 浏览器自动化 | https://github.com/microsoft/playwright/blob/main/LICENSE |
| Chrome / Edge / Chromium | 浏览器验证 | 各发行包及关于页面的许可证声明 |
| Playwright Firefox | 浏览器验证 | https://www.mozilla.org/MPL/2.0/ 及发行包第三方声明 |
| FFmpeg | 录制和编码 | 所用发行包随附许可证，https://ffmpeg.org/legal.html |
| Microsoft YaHei / Arial | 作者机器已有字体 | 字体不作为独立文件附带，使用目标机器已有字体 |
| Artifact Tool | PPT 制作和校验 | Codex 附带制作工具，未重新分发 |
| QEMU / Alpine / Docker / Poppler | Linux 复现及版式检查 | 仅在作者私有验证环境运行，二进制与虚拟磁盘不进入源码或证据包 |

图表和架构图由本工程数据及代码生成；文献引用见报告。论文全文不属于本工程 MIT 源码。
