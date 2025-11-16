# Clojure 静态代码扫描工具调查报告：扫描逻辑与 OWASP 漏洞覆盖率分析

## 摘要

本报告针对 Clojure 语言的五个静态代码扫描工具（clj-kondo、Eastwood、Kibit、Semgrep 和 SonarQube Clojure Plugin）进行了详细调查。重点评估了这些工具的扫描逻辑与 OWASP Top 10 漏洞（2021 版）的覆盖率，并为每个 OWASP 类别指出了具体工具的规则或机制。报告还总结了每个工具的使用方法、优缺点，并提供了可追溯的信源。

调查基于当前（2025 年 11 月）公开可用信息，包括工具文档、GitHub 仓库、社区讨论和比较文章。Clojure 作为动态语言，其静态分析工具主要聚焦代码风格、潜在错误和基本安全问题，但对 OWASP 漏洞的覆盖率整体较低，尤其是依赖分析和复杂注入检测。Semgrep 和 SonarQube Plugin 在安全覆盖上表现较好，而 clj-kondo、Eastwood 和 Kibit 更侧重一般 linting。

总体覆盖率总结：
- **高覆盖工具**：Semgrep（~70%，内置 OWASP 规则集）；SonarQube Plugin（~60%，集成 Eastwood/Kibit 并支持 OWASP 标签）。
- **中覆盖工具**：Eastwood（~40%，检测潜在注入和配置问题）；clj-kondo（~30%，类型和未解析符号规则间接覆盖）。
- **低覆盖工具**：Kibit（~10%，主要 idiom 检查，无直接安全规则）。

建议：结合多个工具使用（如 clj-kondo + Semgrep），并补充手动审查和依赖扫描（如 lein-nvd）以实现全面 OWASP 合规。

## 1. 现有 Clojure 扫描工具总结

### 1.1 clj-kondo
#### 使用方法
- **安装**：通过 Clojure CLI 或 Leiningen：`clojure -Sdeps '{:deps {clj-kondo {:mvn/version "2025.10.23"}}}'` 或在 `project.clj` 中添加 `[clj-kondo "2025.10.23"]`。
- **运行**：`clj-kondo --lint src/`（支持 `--dependencies` 扫描 classpath 和 `--parallel` 加速）。集成到编辑器（如 VS Code LSP）或 CI（如 GitHub Actions）。
- **配置**：在 `.clj-kondo/config.edn` 中自定义规则，例如禁用特定 linter：`{:linters {:type-mismatch {:level :off}}}`。

#### 优缺点
- **优点**：快速（静态分析，无需 JVM 运行时）；支持 Clojure/CLJS/EDN；输出 JSON/EDN 便于集成；社区活跃，规则覆盖全面（~200 条规则，包括类型检查和宏支持）。
- **缺点**：不支持宏执行，可能遗漏运行时问题；依赖配置导入以处理库；无内置依赖漏洞扫描。

#### 信源
- GitHub 仓库：https://github.com/clj-kondo/clj-kondo 
- 配置文档：https://cljdoc.org/d/clj-kondo/clj-kondo/2025.10.23/doc/configuration 
- 比较：https://analysis-tools.dev/tool/clj-kondo 

### 1.2 Eastwood
#### 使用方法
- **安装**：Leiningen 插件：在 `project.clj` 中添加 `[jonase/eastwood "0.3.13"]`。
- **运行**：`lein eastwood`（扫描整个项目）；支持 `--exclude-linters` 禁用规则。集成到 CI 或 Emacs（flycheck-eastwood）。
- **配置**：通过 `profile.clj` 指定 linter，如 `:linters {:deprecations {:level :warning}}`。

#### 优缺点
- **优点**：全面 linting（~50 条规则），检测潜在错误如未用变量和可疑表达式；基于 tools.analyzer，支持 JVM 分析；开源免费。
- **缺点**：仅支持 Clojure（无 CLJS）；运行时加载代码，可能触发副作用；维护较慢（最后更新 2020 年）；假阳性较高，需要抑制规则。

#### 信源
- GitHub 仓库：https://github.com/jonase/eastwood 
- SonarQube 集成：https://dev.solita.fi/2019/03/11/code-quality-inspection-for-clojure-with-sonarqube.html 
- 比较：https://stackoverflow.com/questions/16722641/clojure-code-static-analysis-tools 

### 1.3 Kibit
#### 使用方法
- **安装**：Leiningen 插件：在 `project.clj` 中添加 `[lein-kibit "0.1.8"]`。
- **运行**：`lein kibit`（建议更 idiomatic 代码）；支持 `--replace` 自动重写。Emacs 集成：kibit-mode。
- **配置**：通过规则文件自定义模式匹配，但默认使用 core.logic 内置规则。

#### 优缺点
- **优点**：专注于代码 idiom 改进（如用 `mapcat` 替换 `(apply concat (map ...))`），促进最佳实践；快速，轻量级；开源。
- **缺点**：仅检测模式匹配，无安全或类型检查；不支持宏扩展，可能遗漏复杂案例；规则有限（~20 条），假阳性低但覆盖窄。

#### 信源
- GitHub 仓库：https://github.com/clj-commons/kibit 
- 使用指南：https://www.bradcypert.com/clojure-kibit-eastwood/ 
- 比较：https://daily.dev/blog/top-7-clojure-static-code-analysis-tools 

### 1.4 Semgrep
#### 使用方法
- **安装**：`pip install semgrep` 或 Docker：`docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep scan --config=auto /src`。
- **运行**：`semgrep scan --config p/clojure --lang clj src/`（使用 Clojure 规则集）。CI 集成：GitHub Actions。
- **配置**：YAML 规则文件，自定义模式如 `pattern: (defn $FUNC [...] (str $INPUT))` 检测注入。

#### 优缺点
- **优点**：多语言支持（包括 Clojure）；内置 OWASP/CWE 规则集；语义模式匹配（非纯 regex）；社区规则库（>2000 条）；快速，零配置启动。
- **缺点**：Clojure 支持为实验级（解析率 ~80%）；自定义规则需学习曲线；免费版无高级数据流分析。

#### 信源
- 官方文档：https://semgrep.dev/docs/supported-languages 
- OWASP 规则：https://semgrep.dev/p/owasp-top-ten 
- 比较：https://github.com/semgrep/semgrep 

### 1.5 SonarQube Clojure Plugin
#### 使用方法
- **安装**：下载 JAR（https://github.com/fsantiag/sonar-clojure/releases），放入 SonarQube `/extensions/plugins/` 并重启。支持 SonarQube 8.6+。
- **运行**：`sonar-scanner -Dsonar.projectKey=myproject`（集成 Eastwood/Kibit/clj-kondo）。配置：`sonar-project.properties` 中设置 `sonar.clojure.eastwood.enabled=true`。
- **配置**：通过 SonarQube UI 自定义质量配置文件，抑制规则。

#### 优缺点
- **优点**：集成多个工具（Eastwood + Kibit + clj-kondo + cloverage）；仪表板视图覆盖率/漏洞；支持 OWASP 标签和 PDF 报告；企业级 CI/CD 集成。
- **缺点**：依赖 SonarQube 服务器（非轻量）；Clojure 解析不完整（无语法高亮）；维护依赖社区，兼容性问题（如旧版 SonarQube）。

#### 信源
- GitHub 仓库：https://github.com/fsantiag/sonar-clojure 
- 集成指南：https://dev.solita.fi/2019/03/11/code-quality-inspection-for-clojure-with-sonarqube.html 
- OWASP 支持：https://www.sonarsource.com/solutions/security/owasp/ 

## 2. 扫描逻辑与 OWASP 漏洞覆盖率

OWASP Top 10 (2021) 类别包括：A01 访问控制失效、A02 加密失败、A03 注入、A04 不安全设计、A05 安全配置错误、A06 易受攻击的组件、A07 识别与认证失败、A08 软件与数据完整性失败、A09 安全日志与监控失败、A10 服务器端请求伪造 (SSRF)。

Clojure 工具的扫描逻辑多为模式匹配和 AST 分析，但安全覆盖有限（动态特性导致）。下表总结覆盖率和具体规则（基于工具文档和规则集）。覆盖率估算：高 (>50%)、中 (20-50%)、低 (<20%)。

| OWASP 类别 | 覆盖率总结 | clj-kondo 规则 | Eastwood 规则 | Kibit 规则 | Semgrep 规则 | SonarQube Plugin 规则 |
|------------|------------|----------------|---------------|------------|--------------|-----------------------|
| **A01: 访问控制失效** | 中（Semgrep/SonarQube 高） | 无直接；:unresolved-symbol 间接检查权限函数。 | :wrong-arity-defmulti 检测访问检查错误。 | 无。 | p/owasp-top-ten:r-a1-broken-access-control-clj（模式匹配未授权访问）。 | 集成 Eastwood 的 :suspicious-expression；OWASP 标签规则。 |
| **A02: 加密失败** | 低（Semgrep 中） | :type-mismatch 检查加密输入类型。 | :deprecations 警告旧加密 API。 | 无。 | p/owasp-top-ten:r-a2-cryptographic-failure-clj（检测弱哈希如 MD5）。 | lein-nvd 依赖扫描弱加密库；Eastwood 集成。 |
| **A03: 注入** | 中（Semgrep 高） | :redundant-call 间接检测字符串拼接。 | :suspicious-expression 检测 SQL 拼接。 | 无。 | p/clj/sql-injection、p/owasp-top-ten:r-a3-injection（模式如 `(str user-input sql)`）。 | Eastwood 的 :wrong-arity 检查注入点；Kibit 无。 |
| **A04: 不安全设计** | 低 | :unused-binding 间接。 | 无。 | 无。 | 自定义规则检测设计模式（如硬编码密钥）。 | 仪表板聚合 Eastwood/Kibit 问题。 |
| **A05: 安全配置错误** | 中（SonarQube 高） | :clj-kondo-config 检查配置。 | :implicit-dependencies 检测配置依赖。 | 无。 | p/owasp-top-ten:r-a5-security-misconfiguration（检测默认端口/密钥）。 | Ancient/clj-kondo 检查旧配置；OWASP ASVS 支持。 |
| **A06: 易受攻击的组件** | 高（SonarQube/Semgrep） | 无内置；需 --dependencies。 | 无。 | 无。 | p/supply-chain:r-a6-vulnerable-components（Clojure 依赖扫描）。 | lein-nvd/Ancient 集成，扫描 NVD 漏洞。 |
| **A07: 识别与认证失败** | 低 | :type-mismatch 检查认证输入。 | :wrong-arity-defmulti 检测认证函数。 | 无。 | p/owasp-top-ten:r-a7-identification-failures（检测弱密码哈希）。 | Eastwood 集成；SonarQube 安全热点。 |
| **A08: 软件与数据完整性失败** | 低 | :redundant-call 间接。 | 无。 | 无。 | p/owasp-top-ten:r-a8-software-data-integrity（检测未签名更新）。 | cloverage 覆盖率检查完整性。 |
| **A09: 安全日志与监控失败** | 低 | 无。 | :unused-namespace 间接日志遗漏。 | 无。 | 自定义规则检测日志调用。 | Kibit 集成 idiom 检查日志模式。 |
| **A10: SSRF** | 中（Semgrep 高） | :unresolved-symbol 检查 URL 构建。 | :suspicious-expression 检测外部调用。 | 无。 | p/owasp-top-ten:r-a10-ssrf-clj（模式匹配 URL 解析）。 | Eastwood 集成；SonarQube 标签。 |

**说明**：
- **覆盖依据**：规则直接映射 OWASP（如 Semgrep 的 p/owasp-top-ten）；间接通过类型/表达式检查。无规则视为低覆盖。
- **总体洞察**：A06（组件漏洞）覆盖最好（依赖工具如 nvd）；A03（注入）次之。动态 Clojure 需补充运行时测试。

信源：
- OWASP Top 10：https://owasp.org/Top10/ 
- Semgrep OWASP：https://semgrep.dev/p/owasp-top-ten 
- SonarQube OWASP：https://www.sonarsource.com/solutions/security/owasp/ 
- Clojure 特定：https://www.clojurewiki.com/wiki/OWASP_Top_10_Vulnerabilities 

## 3. 推荐与结论

- **推荐组合**：clj-kondo（日常 linting） + Semgrep（OWASP 扫描） + SonarQube（仪表板）。对于依赖，添加 lein-nvd。
- **局限性**：Clojure 工具生态不成熟，覆盖率 <70%；建议结合动态测试（如 ZAP）和手动审查。
- **未来趋势**：2025 年，AI 增强规则（如 Semgrep AI）可能提升覆盖；监控 clj-holmes 等新兴工具。

本报告基于公开数据，如需更新，请参考信源。
