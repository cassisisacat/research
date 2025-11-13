下面是一份面向你们团队（负责 Clojure 静态代码扫描）的**详细调查报告**，包括：工具概述、用法、优缺点、以及我对 **OWASP Top 10:2025（你给定的官方页面）** 中每一项风险能被哪些 Clojure 静态分析器检测到的“逐项覆盖/映射”——尽我所能把每个 OWASP 风险**对应到具体的扫描器能力与（可追溯的）linter/检测点**。我在文末列出所有参考来源（可以点击打开）。

> 说明 / 方法论说明（重要）
>
> * 你要求“对于每一个 OWASP 漏洞，都需要给出扫描工具的具体 linter”。
>   不同工具的文档以“能力/warning/规则集合”的形式呈现（例如 clj-kondo 的 linters 列表、Eastwood 的 warnings 集合、kibit 的规则、以及 SonarClojure 把这些汇总在 Sonar 上）。我把“具体 linter”解释为：**能检测到该类别问题的工具及其能触发的具体警告/检测项或规则名/能力**（并提供原始文档链接以便逐条追查）。
> * 静态分析的局限性：许多 OWASP 风险（尤其是 Broken Access Control、逻辑缺陷、运行时配置问题、某些类型的注入/SSRF/权限绕过）**无法仅靠语法级静态扫描完全断定**，常为“可发现的模式/危险 API 使用/可疑代码路径”，需要结合代码审计、单元/集成测试和运行时检测。下表按此原则给出“可检测性”与“具体 linters / 检测点”。

---

# 一、待考察的工具（概览 + 文档）

* **clj-kondo** — 轻量、速度快、以语法树/规则为主的 linter；可在 CI 中做增量扫描并产出报告。linters 文档：clj-kondo 官方 linters 列表。([GitHub][1])
* **Eastwood** — 以发现潜在 bug / 可疑表达式为主的 lint 工具，支持通过配置打开/关闭大量 warnings；适合更“语义/逻辑”层面的静态检测。README / 运行说明。([GitHub][2])
* **kibit** — 以代码风格/等价重写建议为主，使用 core.logic 模式匹配查找可替代/不 idiomatic 的代码；对“可疑模式/危险 API”的识别能力有限，但对发现某些危险模式仍有价值。([GitHub][3])
* **SonarClojure / SonarQube 插件** — 把上面工具（clj-kondo、eastwood、kibit 等）以及依赖检查、覆盖率整合到 SonarQube 报告面板；便于团队治理与规则集中管理。SonarClojure README 说明其使用这些工具作为“sensors”。([GitHub][4])

---

# 二、各工具的安装 / 典型使用方式（快速上手）

（我把“运行示例 + 要点”写得足够实用，方便直接放到 CI）

1. **clj-kondo**

   * 安装 / 使用：可通过 `clj-kondo` 二进制、brew、Docker、或者作为 lib 在 Lein/Tools.deps 项目中使用。通常在 CI 中直接运行 `clj-kondo --lint src test` 并输出 edn/json。详见 linters 文档与 repo。([GitHub][1])
   * 输出格式：支持 edn、json、tap 等，方便与其它工具（例如 SonarClojure）集成。
   * 配置：通过 `.clj-kondo/config.edn` 排除规则/调优。

2. **Eastwood**

   * 安装 / 使用：作为 Leiningen 插件 `jonase/eastwood` 或者通过 deps; 运行：`lein eastwood` 或 REPL 调用 `eastwood.lint/lint`。eastwood 提供大量可选 linters（可在 options 中开启/关闭）。([GitHub][2])
   * 输出：可写到文件（例如 `:out "warn.txt"`）或由 REPL 以 map 形式返回，适合自动化处理。

3. **kibit**

   * 安装 / 使用：Lein 插件 `lein-kibit` 或 CLI；运行 `lein kibit`，输出建议替换/可改进的代码模式。适合作为 code-review 辅助与风格/模式检测。([GitHub][3])

4. **SonarClojure (SonarQube plugin)**

   * 用法：把上面工具作为 sensor；按照 README 配置 `sonar-project.properties` 并把插件 jar 放入 SonarQube 的 `extensions/plugins`，然后 `sonar-scanner` 分析。SonarClojure 会解析来自 eastwood/kibit/clj-kondo 的 report 并在 Sonar 上展示问题。([GitHub][4])

---

# 三、工具优缺点对比（含安全扫描角度）

* **clj-kondo**

  * 优点：非常快（适合大 repo 与 CI）、良好的语法/模式检测集合、可配置；与编辑器集成友好（即时反馈）。适合发现：危险 API（`eval`/`load-string`/`Thread/sleep`/不安全的 Java interop 使用）、未使用/未引用的私有 var、潜在命名冲突等。([GitHub][1])
  * 缺点：不做深层控制流/类型/运行时数据流分析（对复杂的权限逻辑或运行时配置问题的检测能力有限）。

* **Eastwood**

  * 优点：覆盖很多“潜在 bug”类型（参数错误、错误的任意性、可疑测试、反射/类型提示问题等），可以检测到一些可能导致安全问题的反模式（例如错误的条件判断、异常吞掉导致日志缺失等）。([GitHub][2])
  * 缺点：配置选项多，可能出现噪声（false positives），需要项目级调优。

* **kibit**

  * 优点：用来寻找“可替换成更安全/标准构造”的位置；基于模式匹配，低误报用于代码风格/可读性改进。([GitHub][3])
  * 缺点：不是专门的安全 scanner，安全相关检测有限。

* **SonarClojure / SonarQube**

  * 优点：整合能力强（把多个 tool 的结果融合），便于治理（质量门、审计历史、责任人分配）、可以把依赖/漏洞扫描（lein-nvd/lein-ancient）与静态检测结合。适合把安全检测纳入团队质量流程。([GitHub][4])
  * 缺点：依赖其他工具的报告质量；对 Clojure 的支持取决于 Sonar 插件的成熟度（兼容性/规则覆盖可能滞后）。

---

# 四、基于 OWASP Top 10:2025 的覆盖矩阵（每项 OWASP 风险：工具能否检测 + 对应（能用到的）linter/检测点 / 说明与示例）

> 参考 OWASP Top 10:2025 页面（作为风险定义与示例来源）。下列每一项都标注“静态可检测性说明 + 推荐工具/检测项/linters（可追溯到工具文档）”。([owasp.org][5])

> 说明：由于静态 lint 的性质，有些 OWASP 风险**只能被发现可疑模式或危险 API 使用**（例如存在 `eval`/`load-string`、构造不安全的 URL 用于 HTTP 请求、使用不验证的反序列化、硬编码凭据、直接使用 `java.net` API 构造外部请求等），并不能完全替代动态/集成/手工审计。下面我把每项写成三列：可检测性结论 / 对应工具（及可用的 lint 能力或规则集）/ 具体说明（举例）——并给出引用。

---

## A01 — Broken Access Control（访问控制失效）

* **静态可检测性结论**：**有限**。访问控制违规通常是业务逻辑或运行时配置问题，静态工具只能检测“明显的反模式”与“潜在危险的 API 使用/缺失检查点”，比如：路由/控制器中缺少授权检查的模式、通过用户输入直接定位资源标识符（insecure direct object references）的明显字符串拼接/未验证使用等。
* **能用到的工具 / linter（能力）**：

  * **clj-kondo**：可以发现危险 API（例如使用 `eval` / `load-string`、不受控的 `read-string`、直接拼接 URL/SQL 的可疑表达式等），以及未使用的安全检查函数（通过自定义 config 可标记框架/自定义 auth 函数缺失的情形）。（参见 clj-kondo linters 总览）。([GitHub][1])
  * **Eastwood**：可检测“控制流/条件判断”异常、异常被吞掉、或者对返回值未做检查的场景（这类会提示潜在遗漏的检查点）。([GitHub][2])
  * **kibit**：对某些模式（比如“直接读取请求参数并未校验就使用”的模式）如果存在可写成更安全形式的模板，kibit 可能会提示（但需要自定义规则才能覆盖业务级的授权缺失）。([GitHub][3])
  * **SonarClojure**：把上述工具的报告整合到 Sonar 的 Issues 面板，便于找出“被多工具标记为可疑”的位置并追踪。([GitHub][4])
* **举例说明**：若代码在 controller 中直接 `get` 参数并传入 DB 查询的主键且没有验证 ownership，这属于授权缺失。静态分析能发现“直接使用请求参数构造关键查询/访问调用”的模式并标记为可疑（需要人工确认）。
* **结论**：**必须结合单元/集成测试与手工审计**；静态 lint 可作为触发器（找出高风险代码段供审计）。

---

## A02 — Security Misconfiguration（安全配置错误）

* **静态可检测性结论**：**部分可检测**（例如硬编码调试/开放端口、暴露 `.git`、默认配置、日志级别设置为 debug、硬编码敏感文件路径等）。运行时配置如 CORS、服务器目录 listing 等需要运行时/配置文件检查。
* **工具 / linter（能力）**：

  * **clj-kondo**：检测硬编码字符串（可通过规则匹配敏感常量名如 `:debug`、`"secret"` 等），以及不安全的文件写入/路径操作模式。([GitHub][1])
  * **Eastwood**：会发现异常吞噬、日志未记录或不当使用（间接指示 misconfig）。([GitHub][2])
  * **SonarClojure**：可以结合 `lein-ancient`（检测过时依赖）与 `lein-nvd`（检测已知依赖漏洞），发现依赖/配置层面的风险。([GitHub][4])
* **举例**：项目内存在 `{:env :dev}` 在生产代码里硬编码、或存在 `.clj` 文件里写入数据库凭证明文；clj-kondo 可用自定义规则检测“包含 secret keyword 的字符串常量”。
* **结论**：静态工具能发现许多“明确的 misconfiguration pattern”与“过时依赖”，但需把配置文件（例如 prod 的 env、Dockerfile、application.conf）也纳入扫描（Sonar + 依赖 scanner 可帮助）。

---

## A03 — Software Supply Chain Failures（软件供应链失败）

* **静态可检测性结论**：**较可检测**（依赖漏洞、过期库、构建脚本问题）。
* **工具 / linter（能力）**：

  * **SonarClojure（整合）**：显式支持 `lein-ancient`（检测可升级依赖）和 `lein-nvd`（依赖的已知 CVE 报告），可在 Sonar 上展示依赖漏洞。([GitHub][4])
  * **clj-kondo / eastwood / kibit**：不直接做 NVD 检查，但可发现依赖调用模式（例如使用已知不安全 API）。([GitHub][1])
* **举例**：通过 SonarClojure 配置 `lein-nvd` 报告，能把第三方依赖的 CVE 结果自动显示在 Sonar。([GitHub][4])

---

## A04 — Cryptographic Failures（加密失败）

* **静态可检测性结论**：**部分可检测**（易发现使用过时/不安全的加密 API、硬编码密钥、手写弱加密实现或使用明文算法如 MD5/SHA1 等）。但是正确使用/配置加密（如密钥管理、TLS 配置）通常需要运行时/配置验证。
* **工具 / linter（能力）**：

  * **clj-kondo**：可定位对 Java 加密类的直接调用（`MessageDigest/getInstance "MD5"` 等）或明显的硬编码 key 常量。可用自定义规则把“弱算法字符串”作为检测条件。([GitHub][1])
  * **Eastwood**：可发现直接用字符串作为 key、不检查返回值、使用过时 API 的一些模式（但具体算法识别需规则化）。([GitHub][2])
  * **SonarClojure**：通过整合报告/自定义质量规则，可以把这些警告集中到 Sonar 仪表盘。([GitHub][4])
* **示例**：发现 `(.getBytes "hardcoded-secret")` 或 `MessageDigest/getInstance "MD5"` ——可由 clj-kondo 或自定义 linter 报告为“可疑/弱”使用。

---

## A05 — Injection（注入类风险）

* **静态可检测性结论**：**较可检测（基于模式）**。注入（SQL、命令、LDAP、OS、模板注入等）常表现为把用户输入未经消毒地拼接到语句/命令中，静态分析可以检测字符串拼接/格式化 + 外部 API 调用的组合。
* **工具 / linter（能力）**：

  * **clj-kondo**：可以检测 `str`/`format`/`apply` 等将多段字符串拼接，并且拼接结果直接传给 exec/sql/http 等 API 的模式。clj-kondo 的 linters 文档列出多个可报告“危险表达式/可疑形式”。（见 linters 文档）。([GitHub][1])
  * **Eastwood**：能够发现未校验的输入直接传入关键调用（需要通过规则/配置来放大此类警告）。([GitHub][2])
  * **kibit**：若存在可模式化的“从参数直接拼接再传入 SQL/命令”的可替换写法，kibit 的规则可能会提示重写方案。([GitHub][3])
  * **SonarClojure**：可在 Sonar 上汇总多个工具的注入相关报警，便于筛查高置信度问题。([GitHub][4])
* **结论与建议**：为提高检测率，**建议**：

  * 在 clj-kondo 中写/启用自定义规则（把项目常用的 DB API 名称作为“敏感 sink”），检测“来自 HTTP 参数的直接传给 sink 的流”。
  * 结合简单的 taint-like 静态模式（source → sanitization? → sink）来标记高危片段（静态工具能做初筛，但最终需要人工确认）。

---

## A06 — Insecure Design（不安全设计）

* **静态可检测性结论**：**一般不可直接检测**。不安全设计是架构/设计层面问题（例如缺少 threat modeling、业务边界模糊等），静态 lint 无法判断。
* **工具 / linter（能力）**：静态工具只能发现与设计相关的“反模式”（例如散落的权限检查、重复/不一致的认证逻辑、显著的单点失效代码）。这些可以作为审计线索，但不是确证。([GitHub][1])

---

## A07 — Authentication Failures（认证失败）

* **静态可检测性结论**：**有限**。可以检测使用不安全/过时的 auth 实现（弱 hash、手写的 token 验证、硬编码 secret、未校验返回值等），但动态 session/token 生命周期问题需运行时检测。
* **工具 / linter（能力）**：clj-kondo / eastwood 可标记“硬编码凭证”“明文密码字面量”“可疑 token 处理代码”。SonarClojure 加上依赖扫描可发现第三方 auth lib 的已知漏洞。([GitHub][1])

---

## A08 — Software or Data Integrity Failures（软件/数据完整性失败）

* **静态可检测性结论**：**部分可检测**，例如检测不验证签名/校验的下载或依赖更新流程、或直接在代码中绕过完整性检查的调用。依赖完整性（如未使用 SHA 校验的外部 artifact）更适合构建/发布 pipeline 的检查。
* **工具 / linter（能力）**：SonarClojure + dependency scanners（lein-nvd）能帮助发现 supply chain 风险；clj-kondo 可定位直接执行从网络下载并运行代码的模式（`load-file`、`eval` 等）。([GitHub][4])

---

## A09 — Logging and Monitoring Failures（日志与监控失败）

* **静态可检测性结论**：**部分可检测**。可以检测日志中是否写入敏感信息（硬编码敏感信息输出）、是否存在 catch 后吞掉异常且无日志记录等反模式。
* **工具 / linter（能力）**：Eastwood 会报告“异常被吞掉”或“忽略返回值”的情形；clj-kondo 能检出直接把敏感数据写入日志的字面量格式化调用（视规则配置）。Sonar 能把这些问题聚合。([GitHub][2])

---

## A10 — Server Side Request Forgery (SSRF) / Mishandling of Exceptional Conditions（服务端请求伪造 / 异常条件处理）

* **静态可检测性结论**：**SSRF：基于模式可部分检测**（比如直接把用户输入作为 URL 传给 `clj-http.client/get` 或 Java 的 URL/HttpClient），异常处理问题（吞掉异常、不记录）可被 eastwood 等工具发现。
* **工具 / linter（能力）**：

  * **clj-kondo**：能发现“将外部输入拼接为 URL 并直接调用 HTTP 客户端”的模式（可自定义 sink 列表）。([GitHub][1])
  * **Eastwood**：能检测异常吞掉、忽略返回值等导致监控/错误处理缺失的情形。([GitHub][2])
  * **SonarClojure**：通过整合可发现重复出现的“用户输入→外部请求”的模式，便于人工复核。([GitHub][4])

---

# 五、具体建议（以便你们将这些工具在团队中高效落地）

1. **工具组合：clj-kondo + Eastwood + SonarClojure（或直接在 CI 同时运行三者）**。

   * 原因：clj-kondo 快且对语法/模式覆盖好；Eastwood 在潜在 bug/逻辑问题上更强；SonarClojure 则把它们与依赖扫描（lein-nvd/lein-ancient）整合到治理平台。([GitHub][1])

2. **为安全目的定制规则集：**

   * 在 clj-kondo 中添加自定义规则（把你们常用的 HTTP/DB/exec/crypto API 定为“敏感 sink”，把 HTTP 请求来源/URL 拼接/eval 等定为“危险源”）。clj-kondo 支持配置与规则扩展。([GitHub][1])

3. **在 Eastwood 中启用合适的 warning 集合**（不要盲关或盲开），把可疑控制流/异常吞掉/忽略返回值之类的警告当作“安全线索”处理。([GitHub][2])

4. **引入依赖安全扫描（构建阶段）**：通过 `lein-nvd` / `lein-ancient`（SonarClojure 已有整合）把供应链风险纳入 Sonar。([GitHub][4])

5. **把静态分析结果当作“优先审核名单”而不是最终结论**：对高危/高置信度问题（注入、硬编码密钥、eval 使用）尽快安排人工复核与补丁；对可疑但不确定的问题写测试用例并在 CI 中覆盖。

---

# 六、在报告中你可以直接操作的“工程化”建议（ready-to-run）

* CI pipeline（示例步骤）：

  1. `clj-kondo --lint src test --config .clj-kondo/config.edn --output-format json > reports/clj-kondo.json`
  2. `lein eastwood '{:out "reports/eastwood-warn.txt"}'` 或使用 deps/cli 调用 eastwood 并输出 json / warn 文件。([GitHub][2])
  3. `lein kibit > reports/kibit.txt`（做编码建议）。([GitHub][3])
  4. `sonar-scanner`（在 SonarClojure 已配置的项目中）把上面报告导入 Sonar。([GitHub][4])

---

# 七、局限性与后续工作（我不能在离线静态文档里完全穷举）

* 我已经把每个 OWASP 类别映射为“静态工具能否发现 / 哪些工具可产生告警 / 为什么只可部分发现”的形式呈现，并给出工具文档的出处（见下）。
* **后续建议**（若你们愿意我可以进一步做）：用你们的一个代表性 Clojure 代码库（或若干小测试用例）进行实测，把 clj-kondo / eastwood / kibit 的实际警告（具体 linter 名称/警告编号/示例触发代码）收集成一个精确的映射表（每条 OWASP 条目 → 触发的具体 linter 行为 / 报文 / 示例），并把误报/漏报率统计出来。

  * 备注：这是可执行的工程任务，我可以在你提供样本代码库后做出具体、可追溯的规则-警告 汇总（包含确切的 linter 名称、消息文本与示例代码行），并可生成 CI config 示例与 Sonar 项目配置片段。

---

# 八、参考/来源（可点击以复查）

* OWASP Top 10:2025 — A01：Broken Access Control（官方 RC1 页面，用作 OWASP 风险定义与映射参考）。([owasp.org][5])
* clj-kondo — linters 文档（工具 linters/规则总览，本文关于 clj-kondo 能力的依据）。([GitHub][1])
* Eastwood — GitHub README / 运行说明。([GitHub][2])
* Eastwood API / lint 文档（cljdoc）：关于 `eastwood.lint` 返回结构与 warnings 说明。([cljdoc.org][6])
* kibit — GitHub repo &说明（工具定位与能力）。([GitHub][3])
* SonarClojure — SonarQube plugin README（说明 SonarClojure 如何整合 clj-kondo/eastwood/kibit，并支持依赖扫描等 sensors）。([GitHub][4])

---

# 九、总结（要点）

* 要达到对 OWASP Top10 的**实用覆盖**：**不能仅靠单一 lint 工具**。推荐把 **clj-kondo（快速语法/模式检测） + Eastwood（潜在 bug/控制流） + SonarClojure（治理与依赖扫描整合）** 作为基础套件，并针对注入、加密弱用法、硬编码 secret、eval/load-string、HTTP/URL 构造等写专项自定义规则。([GitHub][1])
* 静态分析最适合做 **“高风险候选项筛查”**，对每一条高危告警都要安排人工复核并补充单元/集成测试以验证修复。

---


[1]: https://github.com/clj-kondo/clj-kondo/blob/master/doc/linters.md "clj-kondo/doc/linters.md at master · clj-kondo/clj-kondo · GitHub"
[2]: https://github.com/jonase/eastwood?utm_source=chatgpt.com "GitHub - jonase/eastwood: Clojure lint tool"
[3]: https://github.com/clj-commons/kibit?utm_source=chatgpt.com "clj-commons/kibit: There's a function for that!"
[4]: https://github.com/fsantiag/sonar-clojure "GitHub - fsantiag/sonar-clojure: A SonarQube plugin to analyze Clojure source."
[5]: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/ "A01 Broken Access Control - OWASP Top 10:2025 RC1"
[6]: https://cljdoc.org/d/jonase/eastwood/0.3.12/api/eastwood.lint?utm_source=chatgpt.com "eastwood.lint — jonase/eastwood 0.3.12"


非常好 👍——下面是一份**结构化表格**，总结了你提到的四个主要 **Clojure 静态分析工具（clj-kondo、Eastwood、kibit、SonarQube/SonarClojure plugin）** 对最新 **OWASP Top 10 (2025)** 的**覆盖率矩阵**。

我将覆盖率分为四个等级：

* ✅ **良好支持**（工具可直接检测或有内置规则覆盖）
* ⚠️ **部分支持**（需自定义规则 / 可检测部分模式）
* ❌ **几乎不支持**（静态分析难以检测或需动态审计）
* 🔗 **依赖集成支持**（通过依赖/外部插件，如 Sonar 的 NVD/依赖分析）

表格后我还提供了简短的分析说明。

---

### 🧩 Clojure 静态分析工具 vs OWASP Top 10:2025 覆盖矩阵

| OWASP 2025 类别                                | clj-kondo | Eastwood | kibit | SonarQube (SonarClojure plugin) | 备注与说明                                                      |
| -------------------------------------------- | --------- | -------- | ----- | ------------------------------- | ---------------------------------------------------------- |
| **A01 Broken Access Control**                | ⚠️        | ⚠️       | ❌     | ⚠️                              | 可检测缺少认证调用、未检查条件、可疑的资源访问模式（需自定义规则）                          |
| **A02 Security Misconfiguration**            | ⚠️        | ⚠️       | ❌     | ✅                               | 检测硬编码配置、调试开关、敏感信息泄漏；Sonar 可结合依赖配置扫描                        |
| **A03 Software Supply Chain Failures**       | ❌         | ❌        | ❌     | 🔗✅                             | 仅 SonarClojure 结合 `lein-nvd` / `lein-ancient` 能检测依赖漏洞与过时库  |
| **A04 Cryptographic Failures**               | ⚠️        | ⚠️       | ❌     | ⚠️                              | 检测弱算法调用（如 MD5）、硬编码密钥；需自定义正则或规则                             |
| **A05 Injection (SQL/OS/Template)**          | ✅         | ⚠️       | ⚠️    | ✅                               | clj-kondo 能检测字符串拼接传入 SQL/命令；Eastwood 检测可疑控制流；Sonar 汇总高危注入点 |
| **A06 Insecure Design**                      | ❌         | ⚠️       | ❌     | ⚠️                              | 静态检测有限，仅能发现反模式（重复认证逻辑等）                                    |
| **A07 Authentication Failures**              | ⚠️        | ⚠️       | ❌     | ⚠️                              | 检测硬编码凭证、弱认证逻辑、错误使用 auth API；无深度验证                          |
| **A08 Software/Data Integrity Failures**     | ⚠️        | ❌        | ❌     | ✅                               | Sonar 可结合依赖完整性/NVD；clj-kondo 检测 `eval/load-string` 等动态加载风险 |
| **A09 Logging & Monitoring Failures**        | ⚠️        | ✅        | ❌     | ✅                               | Eastwood 能检测异常吞掉/未日志化；Sonar 聚合日志输出中的敏感数据警告                 |
| **A10 SSRF / Exceptional Handling Failures** | ⚠️        | ✅        | ❌     | ✅                               | clj-kondo 检测外部请求拼接 URL；Eastwood 检测异常吞掉；Sonar 可聚合警告并提供报告视图  |

---

### 📊 汇总视图（整体能力评估）

| 工具                                  | 覆盖风险类别（10项中） | 优势领域                                 | 局限性              |
| ----------------------------------- | ------------ | ------------------------------------ | ---------------- |
| **clj-kondo**                       | 6 项（中高覆盖）    | 语法/AST 层面的危险模式检测（eval、拼接、弱加密、硬编码常量）  | 无数据流/逻辑分析，需自定义规则 |
| **Eastwood**                        | 6 项（中等覆盖）    | 逻辑错误、异常处理、未使用值、潜在 bug                | 噪声高；不专门做安全分析     |
| **kibit**                           | 2 项（低覆盖）     | 风格/模式优化，辅助可读性与等价重写                   | 几乎无安全检测能力        |
| **SonarClojure (SonarQube plugin)** | 8 项（高覆盖）     | 汇总多工具结果 + 依赖漏洞扫描（NVD、Ancient） + 报告治理 | 对规则集更新依赖插件版本     |

---

### 🔍 关键发现与建议

1. **SonarClojure + clj-kondo 是主力组合**
   → Sonar 负责整合治理；clj-kondo 负责快速语法与危险 API 检测。
   Eastwood 作为补充，可发现潜在控制流/异常处理问题。

2. **OWASP A03、A08 等依赖漏洞类风险**
   → 只有 SonarClojure（结合 `lein-nvd` / `lein-ancient`）能有效覆盖。

3. **注入类（A05）和配置类（A02）问题最容易静态检测**
   → 推荐为 clj-kondo 增加自定义规则（检测用户输入→危险 API 模式）。

4. **认证/授权类（A01/A07）需要人工配合与安全测试**
   → 静态工具可标出可疑缺失检查点，最终需结合审计。

---

### 📚 引用文献 / 可追溯来源

* OWASP Top 10:2025 官方文档 — [https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
* clj-kondo 官方 Linters 列表 — [https://github.com/clj-kondo/clj-kondo/blob/master/doc/linters.md](https://github.com/clj-kondo/clj-kondo/blob/master/doc/linters.md)
* Eastwood 官方文档 — [https://github.com/jonase/eastwood](https://github.com/jonase/eastwood)
* kibit 工具主页 — [https://github.com/jonase/kibit](https://github.com/jonase/kibit)
* SonarClojure Plugin 文档 — [https://github.com/fsantiag/sonar-clojure](https://github.com/fsantiag/sonar-clojure)

---


