# 留存裁决簿

完全离线，输入与主体均为合成数据。`python -m pip install . --no-build-isolation` 安装；`python -m retaincase demo` 一条命令初始化 SQLite、导入 fixture、计算、生成 JSON/Markdown；`python -m pytest -q` 测试。

`usage-register` 另行冻结留存对象的人员/设备进出扫描，`usage-summary` 只返回原始扫描、人员和设备数，不推断访问会话；这组分析日志不参与可销毁性、交接或删除请求。`fixtures/usage-scans.jsonl` 与 `tests/test_usage.py` 提供离线合成样例。

## 访问会话评估

`usage-assess --db DB --id LOG --gap 120 --contract reported|guaranteed --cutoff 2026-05-02T00:00:00Z --limit 1 --assessment A1` 在已冻结扫描日志上派生设备访问会话：先按 subject+actor+device 把 enter/exit 配成设备访问区间，再把同一 subject+actor 实际重叠或相邻间隔不超过 `gap`（等号也合并）的区间并成会话。只计入报告时间不晚于 `cutoff` 的扫描；截止边界造成的未闭合区间标为待核，不默默算成零会话。重复/缺失出口、enter 不早于 exit、跨设备重叠和不可能的误差交集都给出具体待核原因。

两种口径分别冻结：`reported` 直接用扫描报告时间，回答值班分析员按原始时间线看到的会话数；`guaranteed` 假设每台设备在同一日志内的全部扫描共享一个未知整数秒常数时钟偏移（各设备独立，须同时满足该设备各行的 ±error_seconds），回答全部可行偏移配置下会话数的精确最小值、最大值及可重放的偏移见证。极值由整数超平面排列的完备候选枚举求得，不做随机采样或固定时间网格，成本只取决于区间数而非误差窗口宽度；`usage-verify` 从冻结原始行重新配对并重放见证、核对极值与结论，扫描、阈值或见证被篡改均不通过。

评估绑定冻结的 log_id/源哈希、gap、contract、cutoff、阈值与算法版本（`usage-assess-1.0.0`）：同 assessment_id 同参数幂等，异参数冲突，新日志版本只能另建评估，旧评估不会被新扫描或策略覆盖。该结论独立于留存裁决，`rules.evaluate`、删除请求、交接与回收均不消费它。`fixtures/usage-multi-device.jsonl`、`usage-gap-boundary.jsonl`、`usage-shared-offset.jsonl`、`usage-cutoff.jsonl`、`usage-invalid-exit.jsonl`、`usage-impossible-offset.jsonl` 与 `tests/test_usage_assess.py` 覆盖四行反例、共享/独立偏移、等号边界、多设备交错、无效配对与篡改对账。

数据流：SourceFile 原始字节及哈希 → RawEvent → Subject 与 RuleVersion → Run 内的 Decision、Evidence、Issue → 报告；身份冲突和坏行保留为 Issue。相同文件哈希与事件键幂等。

状态：待接收→已校验→已判定/待核；决策和证据与运行状态事务提交。错误码包括 parse_error、identity_conflict、evidence_gap、rule_conflict、execution_failure。只操作显式沙箱。

首版裁决能力见 `rules.py`。新增的删除请求与保管交接均有持久状态和独立命令。

## 删除请求与保管交接

`request-triage --db DB --id REQ --subjects A,D --due 2099-01-01T00:00:00Z` 把多对象请求冻结到一次裁决，逐对象给出 `erase`、`defer`、`investigate` 义务和请求整体状态；`request-fulfill` 只在本次运行有销毁执行证明时履约。一个对象可销毁而另一个受保全时，请求仍是部分履约，不能用单对象计划代替整单结论。

`handoff-prepare --db DB --id T --recipient receiver-A --subjects D --expires 2099-01-01T00:00:00Z` 冻结接收人、运行和对象哈希；`handoff-ack --db DB --id T --recipient receiver-A --hashes hashes.json --at 2030-01-01T00:00:00Z` 对全部对象核验后产生接受、争议或过期结论。待删除义务阻断移交；已被接受的移交使后续可销毁对象的删除请求产生外部履约义务，多个有效交接则进入调查。`fixtures/operations.json` 给出正常、冲突和部分履约输入。两项子系统在同一 SQLite 控制库中留下可复核的独立记录。

## 接收方删除回执

已接受交接且原裁决允许销毁时，后续删除请求产生 `remote_erase`，区别于本地 `erase`。`recall-open --db DB --id RC --request REQ --transfer T` 按交接与请求的交集冻结外部义务；`recall-submit --db DB --id RC --recipient receiver-A --receipts receipts.json` 逐对象核验交接哈希及接收方 HMAC 回执。控制库保存每次提交的原始摘要、通过或争议原因，以及 pending/partial/disputed/completed 状态。重复事件键不能改写原证明，错误回执不会覆盖已确认对象；只有整批回执完成，`request-fulfill` 才能把对应外部义务计入履约。`fixtures/recall-cases.json` 给出两对象正常、冲突与部分失败场景。接收方密钥在合成配置的 `custody_keys` 中；真实部署应改为独立保管的凭据。

## 裁决与销毁的一致性

期限起点由政策明确选择产生、终止或最后使用事件；后两者只看裁决时刻之前的事件，缺事件时结论为证据不足。日期视为 UTC 当日零时，带时间的事件须含时区偏移并先转换到 UTC；无偏移时间隔离为解析问题。保全令按生效与解除事件回放，未匹配的解除记录也进入证据不足，不能凭它释放资产。依赖闭包阻止仍被使用的源资产销毁。

`plan` 保存清单正文摘要和对应运行 ID。`execute` 只接受最新运行生成、与当前可销毁集合及冻结对象路径和哈希一致的清单；政策字节被直接篡改、重新裁决、清单被改动或目标字节变化时均拒绝销毁。执行只作用于显式沙箱，逐对象记录销毁证明。文件系统删除与 SQLite 台账之间尚无跨资源原子提交，若进程恰在两者之间中断，须人工核对目标和台账后再运行。

每次裁决的 Evidence 关联参与判断的原始事件及来源文件；子对象使源对象继续留存时，依赖边和子对象的保全证据一并传播到源对象。`verify` 会重新读原始来源的对应行，核对事件摘要和内容。只存一个同主体的摘要记录不足以证明来源未被替换。
