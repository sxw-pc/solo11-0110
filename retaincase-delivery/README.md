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

## 字段清单登记

`inventory-register --db <台账> --id <清单号> fixtures/minimization-inventory.csv`
登记本地对象的字段、值与 `direct`、`derived`、`public` 分类，按字节摘要冻结
清单并拒绝未知主体、重复字段及同号改写。`inventory-inspect` 可读回清单。
该流程不改源 CSV，也不改变现有销毁或保全裁决。合成 fixture 和
`tests/test_minimization.py` 覆盖登记、重放和冲突。

每次裁决的 Evidence 关联参与判断的原始事件及来源文件；子对象使源对象继续留存时，依赖边和子对象的保全证据一并传播到源对象。`verify` 会重新读原始来源的对应行，核对事件摘要和内容。只存一个同主体的摘要记录不足以证明来源未被替换。

## 面向分析接收方的最小化交付（本增强副本新增）

`delivery-freeze` 把一次最小化申请冻结到台账（绑定清单摘要、最新裁决 run、接收方、用途、
k 值、路线、可交付字段、泛化层级偏序与字段来源），并在安全时原子产出字段级分析包。
`direct` 字段永不入包；`derived` 字段缺来源即待核，沿可逆链触及 direct 的派生一律排除。
法律保全主体可参与受控派生包且原证据不动；已销毁主体不能从旧清单再导出，证据不足主体
不得冒充可用记录。

单份包按泛化准标识形成等价类并在抑制上限内隔离不足 k 的整行；随后按**内部主体身份**对同一
接收方全部既有包（含已撤销包）计算新旧类非空交集，低于 k 的类不得按原粒度发布——换盐、
换伪标识不改变该结论，缺席主体也不构成可链接类别。`hold_new` 在原粒度出现小于 k 的交集时
暂缓整份新包；`coarsen_new` 在偏序与抑制数内枚举最小信息损失方案（按层级代价、字段名字典序、
抑制人数与稳定序列打破平局），无方案则暂缓。证明含内部等价类与被保护交集，公开报告只给
交集人数和匿名组号。写入经 staging 目录原子 rename，重放不覆盖旧包、不留半包；
`delivery-verify` 独立重算来源、单份 k 与跨包交集，篡改即撤销该申请而不改写旧合法包。
合成 fixture 位于 `fixtures/delivery/`，设计说明见 `docs/delivery.md`。
