# 留存裁决簿

完全离线，输入与主体均为合成数据。`python -m pip install . --no-build-isolation` 安装；`python -m retaincase demo` 一条命令初始化 SQLite、导入 fixture、计算、生成 JSON/Markdown；`python -m pytest -q` 测试。

数据流：SourceFile 原始字节及哈希 → RawEvent → Subject 与 RuleVersion → Run 内的 Decision、Evidence、Issue → 报告；身份冲突和坏行保留为 Issue。相同文件哈希与事件键幂等。

状态：待接收→已校验→已判定/待核；决策和证据与运行状态事务提交。错误码包括 parse_error、identity_conflict、evidence_gap、rule_conflict、execution_failure。只操作显式沙箱。

首版裁决能力见 `rules.py`。新增的删除请求与保管交接均有持久状态和独立命令。

## 删除请求与保管交接

`request-triage --db DB --id REQ --subjects A,D --due 2099-01-01T00:00:00Z` 把多对象请求冻结到一次裁决，逐对象给出 `erase`、`defer`、`investigate` 义务和请求整体状态；`request-fulfill` 只在本次运行有销毁执行证明时履约。一个对象可销毁而另一个受保全时，请求仍是部分履约，不能用单对象计划代替整单结论。

`handoff-prepare --db DB --id T --recipient receiver-A --subjects D --expires 2099-01-01T00:00:00Z` 冻结接收人、运行和对象哈希；`handoff-ack --db DB --id T --recipient receiver-A --hashes hashes.json --at 2030-01-01T00:00:00Z` 对全部对象核验后产生接受、争议或过期结论。待删除义务阻断移交；已被接受的移交使后续可销毁对象的删除请求产生外部履约义务，多个有效交接则进入调查。`fixtures/operations.json` 给出正常、冲突和部分履约输入。两项子系统在同一 SQLite 控制库中留下可复核的独立记录。

### 分批接收与逐对象保管证据

整单确认无法表达"一个对象已由接收方持有、另一个尚未收到"。`handoff-receive --db DB --id T --recipient receiver-A --event-key EVT --receipts recv.json --at 2030-02-01T00:00:00Z` 让接收方按接收事件键提交本次**实际收到**的对象及哈希；`recv.json` 为 `[{"subject":"D","sha256":"..."}]`，未提交的对象保持本地保管，不能由整单状态推断已移交。每次尝试都在只增不改的 `custody_receipt` 表留下 `received`/`disputed`/`rejected` 证据与原因：同一事件原文重放幂等；事件键换内容报 `receive_event_identity_conflict`；对象不在冻结清单、哈希不符、接收人不符、裁决 run 已变化、交接已过期分别登记为可追查的拒绝或争议，且任何尝试都不能改写此前已确认对象。`handoff-inspect` 同时给出整体状态与逐对象的 `pending`/`received`/`disputed` 保管状态；到期不会抹掉实际接收证据。

**晚到接收路线（已选定路线 A：冻结后拒绝接收）**：删除请求一旦冻结，覆盖对象上未履约的**本地 `erase` 义务**即锁定保管权——之后到达的接收事件登记为 `rejected/erasure_request_frozen`，本次请求仍由本地履约，须另开新交接；请求冻结前到达的接收正常登记为 `received`，冻结后该对象产生 `remote_erase`。替代路线（登记请求后争议、本地仍履约）未采用。`remote_erase` 对象已在外部，其替代交接的接收不受冻结守卫阻断，但两个交接都持有接收证据时删除请求进入 `investigate`。

`triage` 在同一请求内逐对象读取保管状态：已收到且裁决可销毁为 `remote_erase`，未收到且可销毁为本地 `erase`，争议对象为 `investigate`；交接 D、E 只收到 D 时，请求结果即 D=`remote_erase`、E=`erase`。旧库中无逐对象证据的 `accepted` 交接在首次访问时按冻结清单一次性回填为遗留接收证据，历史删除请求的冻结义务不被重算。

## 接收方删除回执

已实际收到（存在不可改写的 `received` 接收证据）且原裁决允许销毁时，删除请求对该对象产生 `remote_erase`，区别于本地 `erase`。`recall-open --db DB --id RC --request REQ --transfer T` 按交接与请求的交集冻结外部义务，且只纳入已收到对象；未收到对象不进入外部证明，仍须本地执行台账。`recall-submit --db DB --id RC --recipient receiver-A --receipts receipts.json` 逐对象核验交接哈希及接收方 HMAC 回执。控制库保存每次提交的原始摘要、通过或争议原因，以及 pending/partial/disputed/completed 状态。重复事件键不能改写原证明，错误回执不会覆盖已确认对象；只有整批回执完成，`request-fulfill` 才能把对应外部义务计入履约。`fixtures/recall-cases.json` 给出两对象正常、冲突与部分失败场景。接收方密钥在合成配置的 `custody_keys` 中；真实部署应改为独立保管的凭据。

## 裁决与销毁的一致性

期限起点由政策明确选择产生、终止或最后使用事件；后两者只看裁决时刻之前的事件，缺事件时结论为证据不足。日期视为 UTC 当日零时，带时间的事件须含时区偏移并先转换到 UTC；无偏移时间隔离为解析问题。保全令按生效与解除事件回放，未匹配的解除记录也进入证据不足，不能凭它释放资产。依赖闭包阻止仍被使用的源资产销毁。

`plan` 保存清单正文摘要和对应运行 ID。`execute` 只接受最新运行生成、与当前可销毁集合及冻结对象路径和哈希一致的清单；政策字节被直接篡改、重新裁决、清单被改动或目标字节变化时均拒绝销毁。执行只作用于显式沙箱，逐对象记录销毁证明。文件系统删除与 SQLite 台账之间尚无跨资源原子提交，若进程恰在两者之间中断，须人工核对目标和台账后再运行。

每次裁决的 Evidence 关联参与判断的原始事件及来源文件；子对象使源对象继续留存时，依赖边和子对象的保全证据一并传播到源对象。`verify` 会重新读原始来源的对应行，核对事件摘要和内容。只存一个同主体的摘要记录不足以证明来源未被替换。
