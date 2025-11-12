下面是一份面向你的团队（负责 Clojure 静态代码扫描）的**详细调查报告**，包含：四个目标工具（**clj-kondo、Eastwood、Kibit、SonarQube Clojure 插件**）的功能/用法/优缺点、它们能覆盖 OWASP Top10:2025 哪些类别（以及覆盖深度/限制），并给出可追溯的信源和可执行的落地建议。报告以中文撰写，重要的网络来源我在文中标注引用（你可以点击查看原始文档）。

---

# 执行摘要

* Clojure 常用的静态分析工具中，**clj-kondo**（快速、静态、编辑器/CI 集成）与 **Eastwood**（基于 `tools.analyzer`、更“语义化”）是实际能提供最多代码问题发现能力的两个工具；**Kibit** 偏向风格/惯用法建议，对安全缺陷直接发现能力有限；**SonarQube 的 Clojure 插件** 属社区贡献，能把 Clojure 项目带入 Sonar 生态，但规则集和维护频率参差不齐。([GitHub][1])

* 对 OWASP Top10:2025（A01…A10）的覆盖：静态 linters 可以**有限且有选择地**检测到与代码弱点、危险 API 使用、异常处理、潜在注入相关的模式（例如 `read-string`/`eval`、字符串拼接用在执行/命令构造处、未处理或不安全的异常处理分支、对敏感 API 的错误使用等），但对访问控制策略、运行时配置失误、完整的供应链攻击、真正的认证逻辑缺陷等问题**静态工具本身覆盖薄弱**，需要配合 SCA（依赖扫描）、动态/交互测试与审计流程。OWASP Top10:2025 的官方列表请参考 OWASP。([OWASP][2])

---

# 一、工具概览（逐个说明 — 用法、可检测/不能检测的安全类问题、优缺点、落地建议）

> 说明：下面每一小节都先给简短功能表述，再给「代表性用法 / 常见命令」与「优缺点/安全相关注意点」。引用链接放在小节末。

---

## 1) clj-kondo（静态分析 / lint）

**定位与能力**

* 一个纯静态分析器 / linter，面向 Clojure/ClojureScript/EDN。设计目标速度快、编辑器/CI 友好、不执行被检查代码（不 eval）。适合发现语法/常见 bug、未使用符号、未解析符号、常见错误用法、并且可以通过配置增加/抑制规则。([GitHub][1])

**代表性用法**

* 本地 CLI（示例）：`clj-kondo --lint src`（也可通过 `--lint $(lein classpath)` 建立缓存以加速分析）。可作为 editor-LSP 后端或 CI 中的 lint 步骤。可放置 `.clj-kondo/config.edn` 来定制规则。([ClojureDoc][3])

**能发现的与安全相关的点（示例）**

* 可检测并发/空值/未定义符号、直接使用危险函数（例如对 `clojure.core/read-string` 的“劝阻”/警告可配置或已有 issue 表明其对 read-string 有警告），能通过 `:discouraged-var`、`discouraged-namespace` 等配置告诉开发者避免危险 API。对宏展开/元编程产生的不安全模式可以部分标记（但静态分析有局限）。([GitHub][4])

**优点**

* 非常快、编辑器/CI 易集成、规则可定制、不会执行目标代码（较安全），活跃维护且常用于 CI 与 IDE。([Zenn][5])

**缺点 / 限制（安全角度的重要事项）**

* 由于不执行代码，**对宏复杂展开、运行时值、以及跨模块动态行为感知有限**；针对访问控制逻辑、业务级授权、配置错误（A02）、供应链故障（A03）等问题，静态 lint 能力有限；并且可能对宏或 DSL 产生误报，需要配置或抑制。([ClojureVerse][6])

---

## 2) Eastwood（lint，基于 tools.analyzer）

**定位与能力**

* 更“语义化”的 Clojure linter，使用 `tools.analyzer` / 宏展开与选择性评估（会在某些步骤里 `eval`/require 代码以获得更准确的语义信息），擅长发现疑似 bug、可疑表达式、未按惯例使用的 API 等。适合 CI 扫描以得到更准确（但启动慢、可能涉及运行时侧效果）的结果。([GitHub][7])

**代表性用法**

* 典型用法是通过 Leiningen / Lein plugin：`lein eastwood` 或在 CI 上直接调用 Eastwood。API 也可以从 REPL 调用（`(eastwood.lint/lint opts)`）。文档列出众多 “linters”（例如 `:suspicious-expression`、`constant-test` 等）。([ClojureDoc][8])

**能发现的与安全相关的点（示例）**

* 能更准确地发现「可疑表达式」、「恒为真/假条件」、「错误的异常处理、未使用的返回值、可能的空 deref」等问题；也会提示一些危险模式（例如滥用 `require`/加载时副作用问题）。但东木（Eastwood）在运行时会 `require` 或在 lint 过程中创建命名空间，这会带来“如果被检查的代码在载入时有副作用则可能触发”的风险/限制（文档明确说明此类副作用问题）。([ClojureDoc][8])

**优点**

* 语义更强、误报/漏报在很多场景下比简单静态分析少，适合 CI/审核管线。([GitHub][7])

**缺点 / 限制（安全角度的重要事项）**

* 需要在 JVM 中加载/分析代码（可能执行部分初始化代码或 macro-expansion 导致副作用）；启动慢；对一些宏或元编程仍需手工配置或禁用警告。对访问控制、运行时配置、SCA（依赖链）这类问题仍无直接覆盖。([ClojureDoc][8])

---

## 3) Kibit（风格/惯用法建议）

**定位与能力**

* 主要针对“更惯用/更简洁的 Clojure 写法”提出自动化建议（基于 core.logic 模式匹配），例如将某些 `if` 重写为 `when`、建议替换为更高阶的标准 API 等。不是为安全而设计，但改写有时能减少 bug 表面形式。([GitHub][9])

**代表性用法**

* 常作为 Lein 插件运行：`lein kibit`，或通过 clj-commons/kibit repo 的说明集成到 CI/编辑器。([Clojars][10])

**能发现的与安全相关的点（示例）**

* 对“可疑编码模式”可能间接减小出错面，但**并不专门检测危险 API（如 read-string/eval）或安全 misconfig**。因此对 OWASP 类别的直接覆盖能力很弱。([GitHub][9])

**优点**

* 能提高代码可读性、风格一致性、减少某些类型的人为错误；集成简便。([blog.mattgauger.com][11])

**缺点**

* 安全检测能力有限，更多是重构/优化建议；可能对宏和 DSL 给出不适当建议，需要人工审查。

---

## 4) SonarQube Clojure 插件（社区实现，多个不同仓库）

**定位与能力**

* SonarQube 官方不内置对 Clojure 的支持（需要第三方插件）。市面上存在多个社区插件（例如 `fsantiag/sonar-clojure`、`zmsp/sonar-clojure` 等），目的是把 Clojure 项目纳入 Sonar 扫描面，使 Sonar 展示 code smells、可维护性问题，某些插件可能桥接 clj-kondo / other linters 的结果。([GitHub][12])

**代表性用法**

* 安装插件 jar 到 SonarQube 的 `extensions/plugins/` 并重启；配置 `sonar.sources`、sonar scanner 等。社区讨论显示有一定兼容性问题且维护不一。([GitHub][12])

**能发现的与安全相关的点（示例）**

* 取决于插件实现：部分插件会展示静态分析结果（来自 clj-kondo/Eastwood 等），但**单靠 Sonar 插件本身并不能扩充出更多的安全检测能力**；若 Sonar 插件支持将安全规则（如 Sonar 的 Security Hotspots）映射到 Clojure 代码则可能有部分帮助，但实践中通常不如 Java 平台成熟。社区支持与规则覆盖度、更新频率是关键瓶颈。([Sonar Community][13])

**优点**

* 能把 Clojure 项目纳入企业 Sonar 质量门控、仪表盘与历史趋势。适合希望统一管理所有语言质量的组织。([GitHub][12])

**缺点**

* 插件多为社区维护，可能版本/规则落后、规则覆盖有限。若你需要 Sonar 提供“安全规则”并映射到 OWASP 类别，需要验证插件具体实现并可能需要二次开发或把其他 linter 的输出导入 Sonar。([Sonar Community][13])

---

# 二、工具与 OWASP Top10:2025 的覆盖度（逐项说明与建议）

> 说明方法：我以 OWASP Top10:2025 每一项给出「静态 linter（clj-kondo / Eastwood / Kibit）是否能检测 / 检测举例 / 说明限制」，然后给出补充措施（建议的工具/实践）。OWASP 官方页面见引用。([OWASP][2])

### OWASP A01 — Broken Access Control

* **静态 linters（clj-kondo / Eastwood / Kibit）**：**无法全面检测业务级访问控制缺陷**（例如：控制权逻辑放在错误的层、条件判断遗漏、权限验证绕过等）。静态分析可以发现**明显的代码路径错误**（例如某函数总是返回 true、用错条件判断、未检查拥有者字段等可疑表达式），但对业务上下文（谁能访问什么）需要测试用例、审计与架构分析。([ClojureDoc][14])
* **补充建议**：结合单元/集成测试（含授权用例）、安全设计审查、运行时监控与策略库（应该将访问控制集中化并用单元测试覆盖）。

---

### OWASP A02 — Security Misconfiguration

* **静态 linters**：只能发现代码中硬编码的明显不安全配置（例如明文常量、危险默认值、使用 `*read-eval*` 值为 true 的模式等），但无法发现运行时环境层面的 misconfig（网络、云权限、S3 权限等）。clj-kondo/Eastwood 可提示对危险 API（如 `read-string`、`eval`）的使用。([GitHub][4])
* **补充建议**：引入配置检查（infra-as-code 扫描）、CI 环境的安全基线、以及将敏感配置移入 secrets 管理器。

---

### OWASP A03 — Software Supply Chain Failures

* **静态 linters**：**不负责**。SCA（Software Composition Analysis）工具才是对策。对于 Clojure，**nvd-clojure / lein-nvd**、以及集成 Sonatype OSS Index / Dependabot / Dependency-Check 等工具能对 JAR/依赖进行 CVE 检查。建议把 SCA 加入 CI（例：nvd-clojure、OSS Index、GitHub Dependabot、Dependency-Track）。([GitHub][15])

---

### OWASP A04 — Cryptographic Failures

* **静态 linters**：能在一定程度上检测对弱/禁用算法的使用（如果规则中包含检测特定 API 用法），或发现对错误 API 的调用模式；但大多数 linters（尤其默认配置）**不会**全面识别加密配置的上下文问题（例如错误的 cipher mode、密钥长度不足、错误的密钥管理）。需要专门的安全规则或手工审查。([ClojureDoc][16])
* **补充建议**：制定加密 API 使用准则（并在 clj-kondo 中以 `:discouraged-var` 把旧 API 标为警告），并在代码审计中重点检查 crypto 使用。对关键代码做 peer/security review。

---

### OWASP A05 — Injection

* **静态 linters**：**部分检测**（例如常见模式：字符串拼接用于 SQL/命令构造、直接使用 `java.lang.ProcessBuilder`/`sh` 串接用户输入、使用 `read-string`/`eval` 处理用户数据）。clj-kondo 和 Eastwood 可以被配置/扩展来识别“危险 API”与常见注入模式，但对于数据库参数化/模板上下文，静态分析识别全路径注入仍有挑战。Kibit 对这类问题没特异支持。([GitHub][4])
* **补充建议**：优先替换 `read`/`read-string`/`eval` 等为 `clojure.edn/read` 或安全解析；对外部输入使用参数化 API；增加单元/集成测试覆盖不信任输入路径。

---

### OWASP A06 — Insecure Design

* **静态 linters**：**无法替代设计审查**。Linters 可在实现阶段捕捉某些模式性问题，但“设计层面”缺陷需要 Threat Modeling、设计审查、架构评估。([OWASP][17])

---

### OWASP A07 — Authentication Failures

* **静态 linters**：只会检测到明显的 API 滥用或错误调用（例如忽略空密码检查），但无法判断认证逻辑是否正确（流程/状态/会话管理等）——需要测试或审计。

---

### OWASP A08 — Software or Data Integrity Failures

* **静态 linters**：不能检测到运行时完整性问题（例如构建链被篡改、包签名检查失败）；这类问题应由 SCA、构建签名、artifact 签名与供应链完整性机制来监督（例如构建流水线签名、依赖源白名单）。([OWASP][18])

---

### OWASP A09 — Logging & Alerting Failures

* **静态 linters**：能发现一些日志问题（例如把敏感值直接写到日志、在 catch 中吞掉异常/没有 log），Eastwood 能检测异常处理/空处理类问题。整体上，需要运行时/运营规则校验（SIEM、alerting）。([ClojureDoc][14])

---

### OWASP A10 — Mishandling of Exceptional Conditions

* **静态 linters**：**比较能部分检测**。这类问题（不恰当的异常吞掉、忽略错误分支、failing-open 等）通常与代码层面相关，Eastwood 在这方面有若干 linter（检测异常处理、懒惰捕获、可疑表达式等），clj-kondo 可配置捕获某些“discouraged”用法。总体上，静态检查能发现不少“异常处理不当”模式，但对于业务语义相关的 failing-open 仍需人工/测试复核。([ClojureDoc][14])

---

# 三、结论性覆盖表（简要版 — “✔” 表示有能力发现；“△” 表示能部分/间接发现；“✖” 表示不适合/无法覆盖）

（注：这是面向常见配置/规则集合的总结；实际覆盖度高度依赖你如何配置规则、是否有自定义检测器，以及是否把 SCA 与运行时检测结合）

| OWASP:2025 类别                   |          clj-kondo | Eastwood | Kibit | SonarClojure 插件 | 备注 / 需要补充措施                                                  |
| ------------------------------- | -----------------: | -------: | ----: | --------------: | ------------------------------------------------------------ |
| A01 Broken Access Control       |                  ✖ |        ✖ |     ✖ |             ✖/△ | 需要设计审查 + 测试 / 策略库                                            |
| A02 Security Misconfiguration   |      △（硬编码/危险 API） |        △ |     ✖ |               △ | 需要 infra/config scans                                        |
| A03 Supply Chain Failures       |                  ✖ |        ✖ |     ✖ |               ✖ | 使用 nvd-clojure / OSS Index / Dependabot 等 SCA。([GitHub][15]) |
| A04 Cryptographic Failures      | △（基本 API misusage） |        △ |     ✖ |               △ | 建议制定加密准则并审计代码                                                |
| A05 Injection                   | △（可发现危险 API/字符串拼接） |        △ |     ✖ |               △ | 结合测试、代码 review、runtime detect                                |
| A06 Insecure Design             |                  ✖ |        ✖ |     ✖ |               ✖ | 需要 Threat Modeling                                           |
| A07 Auth Failures               |                  ✖ |        ✖ |     ✖ |               ✖ | 需要测试/审计                                                      |
| A08 Integrity Failures          |                  ✖ |        ✖ |     ✖ |               ✖ | 需 SCA + build-signing                                        |
| A09 Logging & Alerting Failures |                  △ |        △ |     ✖ |               △ | 结合运行时监控/SIEM                                                 |
| A10 Mishandling Exceptions      |                  △ |    ✔（较强） |     ✖ |               △ | Eastwood 对可疑异常/处理有较好检测。([ClojureDoc][14])                    |

---

# 四、落地建议（优先级 + 操作步骤）

## 推荐技术组合（按顺序）

1. **clj-kondo（必装）**：编辑器 + CI 的首选快速 lint。把 `.clj-kondo/config.edn` 作为团队共享规范，包含 `:discouraged-var`（例如 `clojure.core/read-string` / `eval` / 不安全的 Java interop API）和你们希望关注的自定义规则。把 clj-kondo 结果输出为 CI 报表。([ClojureDoc][3])

2. **Eastwood（CI）**：在 CI 中进行深度 lint（例如 nightly 或 PR gate 的慢检查）以捕获更语义化的问题，并把 `lein eastwood` 或 `deps` 集成进 pipeline。注意：在执行 Eastwood 时要保证被扫描代码在加载时不会产生危险副作用（或在隔离环境中运行）。([ClojureDoc][8])

3. **Kibit（可选）**：用于代码风格/惯用法自动化建议，作为“质量”补充（不作为安全检测主力）。([GitHub][9])

4. **SCA（nvd-clojure / lein-nvd / OSS Index）**：对依赖进行 CVE/已知漏洞扫描以覆盖 OWASP A03。把 SCA 扫描作为 CI Gate / nightly 扫描，并对高危漏洞触发安全工单。([GitHub][15])

5. **SonarQube（如果需要统一平台）**：仅在你愿意承担插件维护成本时使用，把 clj-kondo/Eastwood 的输出导入 Sonar（或使用社区插件），以获得集中质量仪表盘。注意：确认所用插件的规则集并评估是否需要二次开发。([GitHub][12])

## 具体 CI 集成示例（最小可运行步骤）

* **clj-kondo (GitHub Actions 示例 snippet)**

  ```yaml
  - name: Run clj-kondo
    run: |
      curl -sSL https://github.com/clj-kondo/clj-kondo/releases/latest/download/clj-kondo-standalone.zip -o /tmp/clj-kondo.zip
      unzip -o /tmp/clj-kondo.zip -d /tmp/clj-kondo
      /tmp/clj-kondo/clj-kondo --lint src test
  ```

  （也可用系统包或 homebrew / native releases）([Zenn][5])

* **Eastwood (Lein)**

  ```bash
  # 安装： add [jonase/eastwood "0.4.0"] 到 :plugins (或使用 uberjar)
  lein eastwood
  ```

  注意：在 CI 中请在隔离环境运行，避免被 scan 的代码在加载时做破坏性操作。([GitHub][7])

* **nvd-clojure / lein-nvd**（依赖 CVE 扫描）

  ```bash
  # Lein plugin
  lein nvd
  # 或在 Clojure CLI 中使用相应动作
  ```

  并把其结果作为 SCA 报表/Fail-on-high severity 规则。([ClojureDoc][19])

## 规则与策略建议（安全实践）

* **禁止/劝阻危险 API**：在 clj-kondo 或 Eastwood 中把 `clojure.core/read-string`、`eval`、任意将用户输入直接转为代码/命令的 API 标为 `:discouraged-var`（并在 CI 中把这些警告提升为阻断或必须解释的安全门）。clj-kondo 已有关于 read-string 的 warning/activity。([GitHub][4])

* **异常处理/日志策略**：创建团队级别的“异常处理与日志”指南（例如不能在 catch 中吞掉异常、不能把 PII 直接写日志），并用 Eastwood 捕获可疑异常处理模式。([ClojureDoc][14])

* **定制规则/自定义检测**：对公司业务的危险 API（比如某些敏感 Java interop）写自定义规则（clj-kondo 支持丰富配置，Eastwood 也可扩展），将关键安全点纳入自动化检测。([ClojureDoc][16])

* **Supply chain / build signing / SBOM**：为所有构建产物生成 SBOM，使用 nvd-clojure/OSS Index/Dependabot 做 CVE 监测，并实行依赖升级策略。([Dependency-Track][20])

---

# 五、风险/局限性（必须向管理层说明）

1. **动态特性与宏**：Clojure 的宏与运行时特性会严重限制静态检测的覆盖率（很多安全问题只有在运行时或在特定上下文才会显现）。clj-kondo 的静态、Eastwood 的部分评估/require 两者都不能完全弥补这一点。([ClojureVerse][6])

2. **误报/假阳性需要规则调整**：在早期上线时会产生误报，需要团队花时间调整 `.clj-kondo/config.edn` / Eastwood 的 linter 集合。([GitHub][21])

3. **Sonar 插件维护/一致性问题**：把 Clojure 接入企业 Sonar 平台需要额外投入（确定插件版本/兼容性/是否持续维护）。([Sonar Community][13])

---

# 六、待办清单（短期/中期/长期）

**短期（0–4 周）**

* 在 CI 中先上线 `clj-kondo --lint src`（把 lint 作为 PR gate），并把常见危险 API（read-string、eval）加入 `:discouraged-var`。([ClojureDoc][3])
* 增加 `lein-nvd`/`nvd-clojure` 的依赖扫描步骤，生成 SCA 报表。([ClojureDoc][19])

**中期（1–3 个月）**

* 把 Eastwood 加入 nightly / 重度 CI 阶段以捕获语义化问题，逐步调整规则集以降低误报。([ClojureDoc][8])
* 制定“不可使用/受限 API”清单与示例替代方案（例如：用 `clojure.edn/read` 代替 `read-string`、避免 `eval`）。([ClojureDocs][22])

**长期（3–12 个月）**

* 如果企业有 Sonar 平台需求，评估并选择合适的 Sonar Clojure 插件，将 linter 输出与 Sonar 集成（并准备维护）。([GitHub][12])
* 建立 Threat Modeling、设计审查与授权测试（弥补静态工具检测不到的 A01/A06/A07 类缺陷）。

---

# 七、重要参考与信源（可追溯）

* clj-kondo — 官方仓库 / README（工具定位、用法、配置说明）。([GitHub][1])
* Eastwood — 官方仓库（lint 列表、实现说明、评估方式）。([GitHub][7])
* Kibit — 官方仓库（面向惯用法的静态分析）。([GitHub][9])
* Sonar-Clojure（社区插件示例 `fsantiag/sonar-clojure`，以及社区讨论 Sonar 默认不支持 Clojure 的说明）。([GitHub][12])
* OWASP Top10:2025（官方 Release Candidate 页面与 A01/A10 等分类说明）。**（你指定要参考的 OWASP 页面）**。([OWASP][2])
* clj-kondo 对 `read-string` 的 issue（示例说明 linter 会对 read-string 提示警告/存在行为）。([GitHub][4])
* clj-kondo 在 MegaLinter / CI 的配置示例（集成/IDE 使用说明）。([Megalinter][23])
* nvd-clojure / lein-nvd（Clojure 依赖漏洞扫描 / SCA）。([GitHub][15])

（上面引用 ID 可直接打开对应页面查阅；若需我把这些链接打包成一个文档/markdown/CI 脚本模板或把 `.clj-kondo/config.edn` 的示例创建出来，我可以在本次回复里直接生成样例配置和脚本 —— 我已经准备好了范例，可以立刻给出。）

---

# 八、附：建议的 `clj-kondo` 安全相关最小示例配置（可直接 copy 到 `.clj-kondo/config.edn`）

> 下面是一个**建议起点**（把危险函数列为 discouraged，并把 read-string 警告提升，实际规则请按团队接受度调整）：

```edn
{:linters {:unknown-symbol {:level :error}
          :unused-private-var {:level :warning}
          :discouraged-var {:level :warning}}

 :config
 {:discouraged-vars
  {; 劝阻读取/执行字符串/不安全 reader
   clojure.core/read-string {:level :error :reason "Don't use read-string on untrusted input; use clojure.edn/read-string or other safe parser"}
   clojure.core/read {:level :error :reason "Don't use read on untrusted input"}
   clojure.core/eval {:level :error :reason "Avoid eval; unsafe with untrusted input"}
   ; 视需要加入对某些 Java interop 的劝阻
   java.lang.Runtime/getRuntime {:level :warning :reason "Avoid runtime.exec on untrusted input"}
   }]
 }
}
```

（如果你要我把这份配置转成更完整的团队模板并放到一个可直接粘贴到仓库的文件，我可以立刻生成该文件内容。）

---

# 九、最后的建议（一句话总结）

把 **clj-kondo + Eastwood + SCA（nvd-clojure）** 作为基础安全流水线（clj-kondo 做快速 PR lint、Eastwood 做深度 CI 检查、SCA 做依赖漏洞扫描），并辅以规范化的“禁止危险 API / 异常处理 & 日志准则”与设计审查/测试策略，能最大限度地把 Clojure 项目对 OWASP Top10:2025 的可检测面牵引到可控范围内；但必须认识到静态工具**无法替代**设计审查、集成/动态测试和运行时监控。([ClojureDoc][3])

---

如果你愿意，我可以立刻（在这次回复里）：

* 生成一个**可直接放到仓库**的 `.clj-kondo/config.edn`（包括安全规则示例、禁用/允许规则、忽略注释策略等）；
* 提供一个 **GitHub Actions**（或你们 CI）的一体化 pipeline YAML 模板，包含 clj-kondo、Eastwood（或 lein eastwood 调用）、nvd-clojure 的步骤与简单失败策略；
* 或者把上面的“工具→OWASP 覆盖表”换成 CSV 或 Excel 表格供团队跟踪和打点（我可以直接生成并提供下载链接）。

你希望我先做哪一项？

[1]: https://github.com/clj-kondo/clj-kondo?utm_source=chatgpt.com "clj-kondo/clj-kondo: Static analyzer and linter for Clojure ..."
[2]: https://owasp.org/Top10/2025/0x00_2025-Introduction/?utm_source=chatgpt.com "Introduction - OWASP Top 10:2025 RC1"
[3]: https://cljdoc.org/d/clj-kondo/clj-kondo/2019.04.04-alpha?utm_source=chatgpt.com "Readme — clj-kondo 2019.04.04-alpha"
[4]: https://github.com/clj-kondo/clj-kondo/issues/2466?utm_source=chatgpt.com "False positive when discouraging read-string in ..."
[5]: https://zenn.dev/uochan/articles/2020-12-09-clj-kondo-hooks?utm_source=chatgpt.com "clj-kondo Hooks入門"
[6]: https://clojureverse.org/t/feedback-wanted-on-new-clj-kondo-macroexpansion-feature/6043?utm_source=chatgpt.com "Feedback wanted on new clj-kondo macroexpansion feature"
[7]: https://github.com/jonase/eastwood?utm_source=chatgpt.com "jonase/eastwood: Clojure lint tool"
[8]: https://cljdoc.org/d/jonase/eastwood/0.3.12/api/eastwood.lint?utm_source=chatgpt.com "eastwood.lint — jonase/eastwood 0.3.12"
[9]: https://github.com/clj-commons/kibit?utm_source=chatgpt.com "clj-commons/kibit: There's a function for that!"
[10]: https://clojars.org/lein-kibit?utm_source=chatgpt.com "lein-kibit"
[11]: https://blog.mattgauger.com/2014/09/15/clojure-code-quality-tools/?utm_source=chatgpt.com "Clojure Code Quality Tools - Matt Gauger"
[12]: https://github.com/fsantiag/sonar-clojure?utm_source=chatgpt.com "fsantiag/sonar-clojure: A SonarQube plugin to analyze ..."
[13]: https://community.sonarsource.com/t/clojure-is-not-supported-by-default-is-it-possible-to-costomize-it-with-https-github-com-fsantiag-sonar-clojure-for-example/22432?utm_source=chatgpt.com "Clojure is not supported by default. Is it possible to ..."
[14]: https://cljdoc.org/d/jonase/eastwood/0.3.12/doc/eastwood-a-clojure-lint-tool?utm_source=chatgpt.com "eastwood - a Clojure lint tool"
[15]: https://github.com/amperity/lein-nvd?utm_source=chatgpt.com "amperity/lein-nvd: National Vulnerability Database ..."
[16]: https://cljdoc.org/d/clj-kondo/clj-kondo/2025.10.23/doc/linters?utm_source=chatgpt.com "Linters — clj-kondo 2025.10.23"
[17]: https://owasp.org/Top10/2025/A06_2025-Insecure_Design/?utm_source=chatgpt.com "A06 Insecure Design - OWASP Top 10:2025 RC1"
[18]: https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/?utm_source=chatgpt.com "A03:2025 Software Supply Chain Failures ..."
[19]: https://cljdoc.org/d/lein-nvd/lein-nvd/2.0.0?utm_source=chatgpt.com "Readme — lein-nvd 2.0.0"
[20]: https://docs.dependencytrack.org/datasources/ossindex/?utm_source=chatgpt.com "Sonatype OSS Index"
[21]: https://raw.githubusercontent.com/clj-kondo/clj-kondo/master/CHANGELOG.md?utm_source=chatgpt.com "https://raw.githubusercontent.com/clj-kondo/clj-ko..."
[22]: https://clojuredocs.org/clojure.core/%2Aread-eval%2A?utm_source=chatgpt.com "read-eval* - clojure.core"
[23]: https://megalinter.io/7/descriptors/clojure_clj_kondo/?utm_source=chatgpt.com "clj-kondo configuration in MegaLinter"
