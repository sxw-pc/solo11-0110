# 留存裁决簿

增强素材副本新增本地留存对象的存储池登记与初始放置：先完成 `init`、`load`、`evaluate`，再运行 `python -m retaincase storage-seed --db <DB> --fixture fixtures/storage-placement.json`，用 `storage-inventory --db <DB>` 查看结果。该流程只为已冻结对象记录池容量、库存字节与摘要，不移动或销毁沙箱文件；同一对象的放置身份不可静默改写。原有裁决、删除请求、交接和回收命令保持可用。

完全离线，输入与主体均为合成数据。`python -m pip install . --no-build-isolation` 安装；`python -m retaincase demo` 一条命令初始化 SQLite、导入 fixture、计算、生成 JSON/Markdown；`python -m pytest -q` 测试。

## 跨失效域副本可用性裁定

每个存储池在登记时声明不可变的 `failure_domain` 与 `tier`（warm/cold）；改域或改层即报 `storage_pool_identity_conflict`。同一失效域内的多份副本只算一个存活点，池目录提供每对象独立路径，跨对象路径冲突被拒绝。`fixtures/sandbox/` 是本地合成对象字节，`fixtures/storage-replica-pools.json` 额外给出同域双冷池与跨域冷池。

`contract-declare --subject A --guard archive_guard|availability_guard --source-root <SANDBOX>` 在最新裁决 run 上冻结保护契约：重新读取实际源文件，绑定对象身份、run、路径、字节数与 SHA-256；guard 一经选择不可改写（`contract_guard_immutable`），新 run 只有在重新核读字节后才能重绑同一契约。

复制是两阶段且可重放的。`replica-reserve` 先核对源文件摘要，再按目标池的独立路径预约容量：容量 = 已放置字节 + 已登记副本字节 + 待落盘预约，两个并发预约不能同时占满最后一份额度（`BEGIN IMMEDIATE` 串行化）。`replica-land` 先把字节写到临时文件、独立重读核对摘要、原子改名后再于最终路径二次核读，最后才写 SQLite；摘要不符的文件被隔离为 `.tampered.*`，预约进入 `rejected` 且释放容量。移动中断（残留 `.part`、改名后未登记）可直接重试，不重复占容量、不把未落盘文件标为可用；已确认副本与历史 `replica_verification` 不被新尝试覆盖。`replica-run` 是两步合一的便捷命令。

`adjudge --storage-root <SANDBOX>` 是暖层退役前的只读裁定：逐对象独立重读每个副本文件并哈希，绝不信任数据库里的 copy_count。`archive_guard` 要求至少一份当前可读、摘要正确的冷存储副本；`availability_guard` 要求至少两个不同失效域各有一份正确可读副本，任一单一失效域退出后仍有存活点。硬阻断（无契约、契约 run 过期、裁决不再冻结、源对象已销毁）给 `indeterminate`；可判定但保护不成立给 `at_risk`，成立给 `protected`，并逐副本给出失效域、文件摘要与逐池容量证据。只有满足契约且退役后仅靠冷层仍满足保护时才给 `can_retire_warm=true`。

`retire-warm` 只是存储层迁移：删除暖层副本文件与暖池放置记录、留存迁移证据，但绝不写 `action=destroy`、不触碰源对象、不会让 `erasure_request` 被错误履约（请求仍按原义务保持 deferred 等状态）；再次调用重放已记录的迁移。删除请求、交接与回执命令的语义不变。

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
