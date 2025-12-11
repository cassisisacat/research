# 调查报告 — DevEco **Code Linter** (ArkTS) 对 OWASP Mobile Top 10（移动版 2024 列表）覆盖情况分析

*作者假设：你是一位负责静态代码扫描的安全负责人。报告面向团队用于评估现有 Code Linter 能力、缺口与可改进项。*
（引用的权威来源：OWASP Mobile Top 10（2024）与 Huawei DevEco Code Linter 规则页与若干规则文档。）([OWASP][1])

---

## 概要结论（快速扫读）

* **Code Linter 提供了一个面向 ArkTS/TS 的静态规则集合（rule sets），其中含有专门的安全规则集 `@security`，并包含大量与加密、不安全算法、弱密钥、危险 API 使用等相关的规则。** 这能较好地覆盖 OWASP Mobile Top 10 中**与加密、弱算法与错误用法相关的项（如 M10: Insufficient Cryptography / M5: Insecure Communication 的部分子类）**。([developer.huawei.com][2])
* **但 Code Linter（静态语法/模式/API 识别）在“供应链、安全配置、运行时授权逻辑、隐私策略、二进制保护、复杂数据流漏报/漏检”等方面存在固有限制**。这些风险需要补充的静态数据流分析(SAST)、软件构建/依赖扫描(SCA)、动态检测/运行时保护(RASP) 与手工审计。([developer.huawei.com][3])

下面按 OWASP Mobile Top 10（移动版 2024 列表）的每一项逐条分析，列出 Code Linter 中能用来“识别或告警”的 **规则 ID（或规则类别）**、检测能力等级（**能/部分能/不能**），并给出建议（规则配置、补充工具或检测方法）。

---

# 逐项分析（OWASP 列表项 → Code Linter 规则 → 评估）

> 注：下文所有 Code Linter 规则来自 DevEco/Huawei 的 Code Linter 规则集（`@security`）与其它内置 ruleSets（`@typescript-eslint`、`@performance`、`@hw-stylistic` 等）中的安全/正确性规则（下面会列出具体可查页面）。详见 Code Linter 规则总览与单条规则文档。([developer.huawei.com][2])

---

## M1 — Improper Credential Usage（不当凭证使用）

**风险要点**：硬编码凭证、凭证泄露、凭证存储在不安全位置、凭证复用等。
**Code Linter 可用规则 / 现有能力：**

* `@security/*` （有若干规则检测“硬编码/明文字符串/常见 secret 模式”及某些危险常量使用 —— 注意：官方页面未列出一个统一 `no-hardcoded-credentials` 名称，但规则集中存在检测不当常量/危险 API 使用的条目。需通过 `rules` 搜索/查看具体条目）。([developer.huawei.com][4])
* `@typescript-eslint/no-unsafe-*` 类（用于发现 `any`/不安全类型返回，间接帮助发现类型误用导致凭证被误处理）。（属于通用规则集）
  **检测能力评估**：**部分能**。Code Linter 能通过静态匹配常见的硬编码字符串模式与危险 API 使用给出告警，但**对动态生成凭证、凭证在外部文件/配置中的泄露、或凭证被误传到不安全通道（跨函数/跨模块数据流）**的检测受限。
  **建议**：
* 在 `code-linter.json5` 中启用/加强对常见 secret 正则检测（若规则集中没有，建议向 Huawei 提议加入或本地自定义规则）。
* 配合 SCA/秘密扫描工具（例如 git-secrets、trufflehog）对历史提交和二进制进行扫描；对 CI 集成 secrets scanning。
  **证据/参考**：Code Linter 支持规则集和自定义规则配置说明。([developer.huawei.com][2])

---

## M2 — Inadequate Supply Chain Security（供应链安全不足）

**风险要点**：第三方依赖被注入恶意代码、供应链依赖版本易受漏洞影响、构建管道被劫持等。
**Code Linter 可用规则 / 现有能力：**

* **基本上无**：Code Linter 主要做源代码静态检查（ArkTS/TS）并不包含完整的依赖 SCA（Software Composition Analysis）或包签名检查规则。
  **检测能力评估**：**不能/有限**。静态规则可通过检测不安全的 `eval`、直接从远程加载脚本、或可疑仓库 URL 等代码模式识别部分可疑行为，但无法替代 SCA。([developer.huawei.com][2])
  **建议**：
* 在流水线中加入专门的 SCA 工具（例如 OSS-Fuzz、Snyk、Dependabot、OSS index）和 SBOM 生成与验证。
* 在 Code Linter 配置中加入对“从 HTTP 拉取脚本”、“动态远程加载”等模式的严检规则（若已有相关规则，设置为 `error`）。
  **备注**：Huawei 文档提到 DevEco 可用于“端云一体化工程优化/构建模板”，但并未替代 SCA 的功能。([developer.huawei.com][5])

---

## M3 — Insecure Authentication/Authorization（不安全的认证/授权）

**风险要点**：错误的身份验证流程、缺失权限检查、错误的 access control、客户端信任敏感逻辑 等。
**Code Linter 可用规则 / 现有能力：**

* `@security/specified-interface-call-chain-check`（示例：对指定接口的调用链检测规则，可用于识别对敏感接口未经校验即调用的模式）。([developer.huawei.com][6])
* `@typescript-eslint` 的若干正确性规则可以帮助发现类型/异常处理不当，但**并不直接判断业务逻辑的授权正确性**。
  **检测能力评估**：**部分能（浅层）**。Code Linter 可以检测“直接调用敏感 API/接口而未做前置校验”的常见模式（基于规则模板/调用链配置），但**对复杂业务授权逻辑（例如基于角色/资源的动态权限检查）无法静态完全判定**，需要数据流/语义理解或手工审计。([developer.huawei.com][6])
  **建议**：
* 利用 `specified-interface-call-chain-check` 类规则为常见敏感 API（如删除/转账/敏感数据导出）定义检测链与白名单。
* 补充带有 taint/数据流分析能力的 SAST 工具或手工审计关键组件。

---

## M4 — Insufficient Input/Output Validation（输入/输出校验不足）

**风险要点**：未对外部输入做校验导致注入、路径遍历、越权等。
**Code Linter 可用规则 / 现有能力：**

* `@typescript-eslint` 和 `@correctness` / `@security` 中存在用于发现 **不安全的 `eval`/动态模板/字符串拼接**、**未做边界检查** 的规则（例如检测 `innerHTML`/直接构造 SQL 字符串的模式——视规则库具体条目而定）。
  **检测能力评估**：**部分能**。模式匹配和简单静态检查（例如发现 `eval`、字符串拼接用于构造命令、URL、文件路径等）能被发现，但复杂的输入验证缺失（例如逻辑路径、正则/限制不当）需要更深的数据流分析和上下文。
  **建议**：
* 打开/强化 `@security` 中与 injection、eval、unsafe-template 有关的规则。
* 对用户输入到敏感 sink（文件系统、shell、数据库、网络）之间的**跨函数数据流**使用支持 taint analysis 的 SAST。

---

## M5 — Insecure Communication（不安全通信）

**风险要点**：未使用 TLS、使用不安全的 TLS 配置、证书校验绕过、明文 HTTP 等。
**Code Linter 可用规则 / 现有能力：**

* 现有 `@security` 包含多条与加密算法/模式不安全相关的规则（`no-unsafe-hash`、`no-unsafe-aes`、`no-unsafe-dh` 等），以及可能检测“使用 HTTP 明文或禁用证书验证”的 API 模式（需确认具体规则 ID）。例如不安全哈希规则：`@security/no-unsafe-hash`。([developer.huawei.com][7])
  **检测能力评估**：**部分能**。Code Linter 很擅长检测**使用不安全加密算法或弱密钥**（见 M10），但**对网络通信层面的配置（如 TLS 版本、证书校验是否被显式跳过）**能否准确识别取决于是否存在对应规则匹配对客户端网络调用和参数（例如 `setAllowAllCertificates(true)`）的检测。
  **建议**：
* 在规则集中查找/启用针对“禁用证书校验”、“使用 http:// URL” 的规则；如果不存在，建议通过自定义规则补充。
* 对运行时的 TLS 配置与证书问题，结合动态测试（运行时监控、抓包）与依赖库配置审查。

---

## M6 — Inadequate Privacy Controls（隐私控制不足）

**风险要点**：过度收集用户数据、未加密敏感 PII、本地存储明文敏感数据、无适当权限说明等。
**Code Linter 可用规则 / 现有能力：**

* Code Linter 可检测静态 **将敏感字段写入本地存储（如 LocalStorage / 文件）** 的直接模式，或使用不恰当存储 API 的代码；但对“是否属于 PII/是否过度收集”这类语义判断**无法自动完整判断**。
  **检测能力评估**：**部分能**。能发现明显的敏感数据明文写入/未加密存储模式，但对“隐私策略合规性/最小化收集”无法静态判定。
  **建议**：
* 将常见 PII 字段名/变量名（如 `idCard`, `phoneNumber`, `email`, `address`）纳入自定义规则匹配，并对写入本地文件/数据库的操作加告警。
* 结合手动审计与隐私自动化测试（privacy linting / PII detection）工具。

---

## M7 — Insufficient Binary Protections（二进制保护不足）

**风险要点**：未启用代码混淆、未签名、调试信息泄露、可逆工程风险（crash logs 含敏感信息）等。
**Code Linter 可用规则 / 现有能力：**

* Code Linter 主要定位源代码层面，**不负责二进制混淆/签名/打包设置**的检测（这些通常在构建配置或 CI/CD 层面控制）。但可以发现“调试日志/打印语句/敏感输出仍在代码中”的模式（例如 `console.log(secret)`）。
  **检测能力评估**：**部分能（仅源代码层面的日志/调试信息检测）**。无法直接验证 APK/HAP/HSP 打包签名或是否启用混淆、是否包含调试符号。
  **建议**：
* 在 Code Linter 中启用规则检测 `console.log`/`print` 输出敏感变量。
* 在构建管道加入二进制检查（签名、混淆工具检查、符号表剥离）。

---

## M8 — Security Misconfiguration（安全配置错误）

**风险要点**：默认配置不安全、权限过宽、调试/测试开关未关、错误的 Android/iOS/HarmonyOS 权限清单配置等。
**Code Linter 可用规则 / 现有能力：**

* Code Linter 能检测源码中可见的不安全常量（如 `DEBUG = true`）、以及代码级别的危险配置使用。但**对于平台级配置文件（manifest / build profiles / packaging），除非 Code Linter 支持解析这些文件并有规则，否则检测有限**。Huawei 文档提及 Code Linter 可配置忽略/检查某些文件类型，但并未表明能全部覆盖所有打包/manifest 配置项。([developer.huawei.com][2])
  **检测能力评估**：**部分能**。能检查常见代码级错误配置，但对平台或运行时配置的全面检测需补充工具（manifest linting、static config scanning）。
  **建议**：
* 扩展扫描范围把项目的 manifest、build 配置也纳入检查（如果 Code Linter 已支持，添加对应 `files` 配置；否则建议用专门的配置 linting 工具）。
* 在 CI 中增加配置硬化检查（例如检测不必要权限、未限制的 Intent/DeepLink、导出组件等）。

---

## M9 — Insecure Data Storage（不安全的数据存储）

**风险要点**：敏感数据（凭证、PII、密钥）在本地明文存储、使用弱加密、权限不当的文件访问等。
**Code Linter 可用规则 / 现有能力：**

* 与 M10（加密）相关的规则集合：`@security/no-unsafe-hash`, `@security/no-unsafe-aes`, `@security/no-unsafe-dh`, `@security/no-unsafe-rsa-key`, `@security/no-unsafe-dsa-key` 等，能够检测**使用不安全算法/模式/密钥长度**的代码。([developer.huawei.com][7])
* 可检测直接使用明文文件写入模式（例如直接写入 `/data/...`、`localStorage.setItem('token', token)`）的规则（如有对应规则或需自定义）。
  **检测能力评估**：**能（在加密与危险存储模式上覆盖较好）**。对“是否属于敏感数据/是否充分加密”做出具体建议时，Code Linter 的加密规则相对成熟；但对密钥管理（KMS 使用/硬件密钥）或运行时泄露仍需结合其他工具。
  **建议**：
* 启用 `@security` 中所有 `no-unsafe-*` 密钥/算法规则，并将告警级别设为 `error`。([developer.huawei.com][7])
* 补充密钥管理审计（确保使用平台安全存储或 KMS）。

---

## M10 — Insufficient Cryptography（加密不足 / 不当）

**风险要点**：使用 MD5/SHA-1/3DES/ECB/短密钥长度/不安全随机数等。
**Code Linter 可用规则 / 现有能力：**

* **大量现成规则**：例如 `@security/no-unsafe-hash`（禁止 MD5、SHA-1 等）、`@security/no-unsafe-3des`、`@security/no-unsafe-aes`（禁止 AES/ECB 模式）、`@security/no-unsafe-dh`（DH 不安全参数）、`@security/no-unsafe-rsa-key` / `no-unsafe-dsa-key`（不安全密钥长度）的单条规则页面均已存在于 Huawei 文档。([developer.huawei.com][7])
  **检测能力评估**：**能（覆盖良好）**。在**规则显式列举不安全算法/模式/密钥长度**的情形下，Code Linter 能准确告警并给出正反例与修复建议。该点是 Code Linter 的强项。
  **建议**：
* 将这些规则纳入 `@security/recommended` 或 `@security/all` 并把严重等级设为 `error`。
* 对于使用第三方加密库的场景，确保规则能识别库的常见错误用法（必要时补充额外规则）。
  **证据/参考**：`no-unsafe-hash`、`no-unsafe-aes`、`no-unsafe-3des`、`no-unsafe-dh`、`no-unsafe-rsa-key` 等规则文档。([developer.huawei.com][7])

---

## 规则索引（示例，便于团队检索）

下面是可立即在 Huawei 文档站点检索到的若干代表性规则页面（示例引用）——你可以把这些规则加入项目的 `code-linter.json5` 中并设置告警级别：

* `@security/no-unsafe-hash`（禁止 MD5/SHA1 等不安全哈希）。([developer.huawei.com][7])
* `@security/no-unsafe-aes`（禁止 AES-ECB/不安全模式）。([developer.huawei.com][8])
* `@security/no-unsafe-3des`（禁止 3DES/ECB 等）。([developer.huawei.com][9])
* `@security/no-unsafe-dh`（禁止不安全 DH 参数）。([developer.huawei.com][10])
* `@security/no-unsafe-rsa-key` / `no-unsafe-dsa-key`（检测弱 RSA/DSA 密钥长度）。([developer.huawei.com][11])
* `@security/specified-interface-call-chain-check`（指定接口调用链检查）。([developer.huawei.com][6])
* Code Linter 规则总览 / 如何配置 `code-linter.json5`。([developer.huawei.com][2])

---

## 工具能力的总结表（简洁版）

| OWASP 项目  | Code Linter 检测能力 | 主要可用规则（示例）                                                                                                             | 需补充的检测方式                          |
| --------- | ---------------: | ---------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| M1 凭证使用   |              部分能 | 自定义 secret 模式 / `@security` 常量检测                                                                                       | secrets-scanner（SAST+git history） |
| M2 供应链    |            不能/有限 | 无直接 SCA 规则                                                                                                             | SCA（Snyk/OSS-Scan）、SBOM           |
| M3 认证/授权  |          部分能（浅层） | `specified-interface-call-chain-check`                                                                                 | 深层 SAST/手工审计                      |
| M4 I/O 验证 |              部分能 | `@typescript-eslint` + `@security` injection 规则                                                                        | taint analysis                    |
| M5 通信安全   |              部分能 | `no-unsafe-hash`、算法规则；（需查具体 TLS 规则）                                                                                    | 运行时/配置扫描、TLS 测试                   |
| M6 隐私     |              部分能 | 检测 明文写入 / 敏感字段写入                                                                                                       | PII detection + 隐私审计              |
| M7 二进制保护  |        部分能（代码日志） | 日志/打印检测规则                                                                                                              | 二进制检查（签名/混淆/剥离）                   |
| M8 配置错误   |              部分能 | 代码中可见 config 检测                                                                                                        | Manifest/config lint + CI 校验      |
| M9 数据存储   |        能（在加密规则上） | `no-unsafe-*` 加密规则                                                                                                     | 密钥管理审计                            |
| M10 加密    |          能（覆盖较好） | `no-unsafe-hash`, `no-unsafe-aes`, `no-unsafe-3des`, `no-unsafe-dh`, `no-unsafe-rsa-key` 等。([developer.huawei.com][7]) | -                                 |

---

## 配置与执行建议（用于团队落地）

1. **默认规则集配置**：项目根 `code-linter.json5` 中显式引入：

   * `plugin:@typescript-eslint/recommended`（通用）
   * `@performance/recommended`（性能）
   * `@security/recommended`（安全）——并将关键的 `no-unsafe-*` 规则设为 `error`。
     例子与配置语法见 DevEco 官方规则说明。([developer.huawei.com][2])

2. **把“高价值”安全规则提升为 error**：如 `@security/no-unsafe-hash`, `@security/no-unsafe-aes`, `@security/no-unsafe-3des`, `@security/no-unsafe-dh`, `@security/no-unsafe-rsa-key`。这能在 CI 失败前拦截最危险的加密错误。([developer.huawei.com][7])

3. **补充扫描链**：Code Linter + SCA（依赖漏洞）+ secrets scanner + taint-capable SAST + 动态测试（如模拟 TLS、权限校验） 的组合，能显著降低剩余风险。

4. **针对 M3/M4/M6（业务逻辑/数据流/隐私）建立审计流程**：自动化工具发现问题后配合手工代码审计/安全评审，尤其是跨模块/跨进程的数据流路径。

5. **定期拉取 Huawei 的规则变更说明**：DevEco 会不时新增规则（release notes 提到新增安全/性能/正确性规则），把规则变更同步进团队规则库，以保持检测覆盖随平台演进。([developer.huawei.com][12])

---

## 附：如何查找与验证单条规则（实务步骤）

1. 打开 Huawei Code Linter 规则总览页（Code Linter Check Rules），定位 `@security` 规则集。([developer.huawei.com][2])
2. 在规则集中搜索关键字（如 `hash`、`rsa`、`dh`、`3des`、`certificate`、`http`、`secret`）以定位细则页面（每条规则包含正反例与 config 样例）。例如 `no-unsafe-hash` 页面说明禁止 MD5/SHA1。([developer.huawei.com][7])
3. 在 `code-linter.json5` 中按项目需求启用规则集并覆盖某些规则的告警等级（示例文档中已有配置样例）。([developer.huawei.com][2])

---

## 结论（一句话总结）

* **Code Linter 在“加密/算法/不安全 API 使用”方面覆盖优秀（M10、M9 的一部分）**，并提供了可配置的 `@security` 规则集合用于 ArkTS。([developer.huawei.com][7])
* **对于供应链安全、复杂的认证/授权逻辑、运行时配置与二进制保护等（M2、M3、M7、M8）需要额外工具或手工审计来补强**；建议把 Code Linter 当作 SAST 的“第一道网”，并与 SCA、secrets scanning、运行时测试及手工审计联动。([developer.huawei.com][3])

---

如果你愿意，我可以立刻为你做下面几件事（选择其一或多个，我会在本次响应里直接完成）：

1. 输出一份 **`code-linter.json5` 推荐模板**（包含 `@security` 关键规则开启与告警等级设置），以便直接放入 ArkTS 项目根目录。
2. 针对你们当前最关心的 OWASP 项（比如你最先想防哪几项），我可以**基于现有规则名生成一份待开启规则清单**（包含规则 ID 与配置建议）。
3. 生成一个**CI 阶段检测流水线建议**（哪些工具按步骤串联：Code Linter → secrets scanner → SCA → taint-SAST → 测试）。

你想先要哪一种输出？（直接回复 1 / 2 / 3 / 或者“都要”——我会把对应结果直接贴出）。

[1]: https://owasp.org/www-project-mobile-top-10/ "OWASP Mobile Top 10 | OWASP Foundation"
[2]: https://developer.huawei.com/consumer/en/doc/harmonyos-guides-V14/ide-codelinter-rule-V14?utm_source=chatgpt.com "Code Linter Check Rules"
[3]: https://developer.huawei.com/consumer/cn/doc/best-practices/bpta-stability-ide-static-detection?utm_source=chatgpt.com "使用DevEco Studio静态检测编码规范"
[4]: https://developer.huawei.com/consumer/cn/doc/harmonyos-guides/ide-security?utm_source=chatgpt.com "安全规则@security-Code Linter代码检查规则"
[5]: https://developer.huawei.com/consumer/cn/doc/harmonyos-releases/deveco-studio-new-features-502?utm_source=chatgpt.com "新增和增强特性-DevEco Studio-HarmonyOS 5.0.2(14)"
[6]: https://developer.huawei.com/consumer/en/doc/harmonyos-guides/ide-specified-interface-call-chain-check-V13?utm_source=chatgpt.com "security/specified-interface-call-chain-check"
[7]: https://developer.huawei.com/consumer/en/doc/harmonyos-guides/ide_no-unsafe-hash-V13?utm_source=chatgpt.com "security/no-unsafe-hash"
[8]: https://developer.huawei.com/consumer/cn/doc/harmonyos-guides/ide_no-unsafe-aes?utm_source=chatgpt.com "security/no-unsafe-aes"
[9]: https://developer.huawei.com/consumer/en/doc/harmonyos-guides/ide-no-unsafe-3des?utm_source=chatgpt.com "@security/no-unsafe-3des-@security: Security Rules-Code ..."
[10]: https://developer.huawei.com/consumer/en/doc/harmonyos-guides/ide_no-unsafe-dh-V13?utm_source=chatgpt.com "security/no-unsafe-dh-@security: Security Rules-Code Linter ..."
[11]: https://developer.huawei.com/consumer/cn/doc/harmonyos-guides/ide_no-unsafe-rsa-key?utm_source=chatgpt.com "@security/no-unsafe-rsa-key-安全规则 ..."
[12]: https://developer.huawei.com/consumer/cn/doc/harmonyos-releases/deveco-studio-new-features-600?utm_source=chatgpt.com "新增和增强特性-DevEco Studio-HarmonyOS 6.0.0(20)"
