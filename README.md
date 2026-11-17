# 留存裁决簿

完全离线，输入与主体均为合成数据。`python -m pip install . --no-build-isolation` 安装；`python -m retaincase demo` 一条命令初始化 SQLite、导入 fixture、计算、生成 JSON/Markdown；`python -m pytest -q` 测试。

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

`plan` 保存清单正文摘要和对应运行 ID。`execute` 只接受最新运行生成、与当前可销毁集合及冻结对象路径和哈希一致的清单；政策字节被直接篡改、重新裁决、清单被改动或目标字节变化时均拒绝销毁。执行只作用于显式沙箱。每次裁决的 Evidence 关联参与判断的原始事件及来源文件；子对象使源对象继续留存时，依赖边和子对象的保全证据一并传播到源对象。`verify` 会重新读原始来源的对应行，核对事件摘要和内容。

## 可恢复的本地多对象销毁

`execute` 在删除前先冻结一次执行尝试（attempt）：校验最新 run、计划正文、全部目标路径与哈希，任何一项不满足都不会移动或删除任何文件；随后把每个对象逐一移入该尝试独占的隔离区 `.retaincase-quarantine/<attempt>/`，普通交付路径不会读取它。每个对象在移动前先写入包含已核验哈希的移动意图，移动后再写隔离证据，因此 `pending → moving → quarantined` 的任意中断都可由数据库重放。只有全部对象都带可核实哈希地隔离后，才按尝试开始时冻结的恢复策略做最终处置。

- `--recovery-policy complete_on_recovery`（默认）：全部隔离后继续完成不可逆销毁；每个对象在删除隔离字节的同一事务内落一条 `execution_proof`。
- `--recovery-policy restore_on_recovery`：同一状态下按哈希把全部文件恢复原路径，并把尝试标为 `restored`、`fulfilled=False`；绝不伪造销毁证明。
- `recover --db DB --sandbox DIR`（或 `--attempt ID`）幂等重放中断尝试，策略不能更改。两条路线只在“全部对象均已隔离且证据完整”时成立；仅隔离了一部分时两条路线都收敛为 `partial`（把已隔离对象核验后放回、未移动对象保持原样），不声称整单完成。
- 隔离字节损坏、或原路径被新文件占用时进入 `disputed`：不覆盖新文件、不删除争议字节、不产生销毁证明。
- 同一沙箱的执行由进程级排他锁串行化，并发调用得到 `sandbox_execution_busy`；不同计划若与进行中的尝试重叠对象，会得到 `object_claimed_by_other_attempt`，旧尝试的隔离文件不会被新计划认领。
- `verify-attempt --db DB --attempt ID`、以及 `verify` 的 `attempts` 字段，按字节重放核对每个隔离/销毁/恢复结论；`execution` 旧表的行一律标为 `protocol="legacy"`、`recoverable=false`，只用于旧协议展示，不参与恢复或履约。
- `request-fulfill` 只消费属于本次 run、与计划/对象身份对应的最终销毁证明；中断中的隔离以 `pending_local_execution` 单独报告，绝不算作已履约。本地隔离与销毁不改变远端交接/回收义务，后者仍只认接收方回执。

