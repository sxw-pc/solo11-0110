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

`plan` 保存清单正文摘要和对应运行 ID。`execute` 只接受最新运行生成、与当前可销毁集合及冻结对象路径和哈希一致的清单；政策字节被直接篡改、重新裁决、清单被改动或目标字节变化时均拒绝销毁。执行只作用于显式沙箱，逐对象记录销毁证明。文件系统删除与 SQLite 台账之间尚无跨资源原子提交，若进程恰在两者之间中断，须人工核对目标和台账后再运行。

每次裁决的 Evidence 关联参与判断的原始事件及来源文件；子对象使源对象继续留存时，依赖边和子对象的保全证据一并传播到源对象。`verify` 会重新读原始来源的对应行，核对事件摘要和内容。只存一个同主体的摘要记录不足以证明来源未被替换。

## 跨法域保留规则

`jurisdiction_origin` 与 `jurisdiction_transfer` 事件把对象的持有地回放成半开区间；`as_of` 的适用法域集合由来源事件、转移时点和对象标签推导，不按导入顺序猜测。未知、重叠或相互矛盾的归属进入待核。每个法域按带生效区间的政策版本选择期限起点；`created` 只认该法域自己的产生事件，证据缺失不能借另一法域补足。保全令与依赖闭包独立生效。

责任合同在 run 中冻结并记录授权依据（CLI 的 `--contract`、`--authority`，或配置的 `jurisdiction_contract`、`jurisdiction_authority`）：

- `concurrent`：所有仍有效的来源地与持有地期限都必须届满；
- `single_successor`：只有在冻结的转移事件带有可核验的 `succession` 记录（依据字段齐全，证据事件键存在于来源）时才排除原持有地，否则仍按并存处理。

`fixtures/jurisdiction-config.json` 与 `fixtures/jurisdiction-events.jsonl` 是合成样例：对象 D 在 J1 按产生日起 365 天（2026-06-15 届满），在 J2 按终止日起 30 天（2026-05-15 已届满）。`as_of` 为 2026-06-01 时，`concurrent` 结论为冻结，`single_successor` 在承接证据可核验时可销毁。`report` 逐法域展示政策版本、起点事件、届满日、承接证明与排除依据；`verify` 核对政策摘要、起点/承接事件仍指向来源行，以及 run 快照未被改写。旧 run 不因迟到事件改变。

