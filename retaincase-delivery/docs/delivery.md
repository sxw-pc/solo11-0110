# 面向分析接收方的最小化交付（增强副本）

本目录是留存裁决簿的独立增强副本：原始 `retaincase/` 包与 `fixtures/` 原始清单保持不变，
最小化交付能力在副本内新增，入口挂在 `minimization.py`、`rules.py`、`requests.py`，
包生成与跨包核算集中在新增的 `retaincase/delivery.py`，CLI 挂在 `__main__.py`。

## 威胁模型

同一接收方可以反复申请同一批留存对象的分析包。单份包即使满足 k 匿名，两份包的等价类
交叉也可能缩成单人，从而重新暴露主体。换伪标识、换盐不构成交叉发布安全：交叉核算一律
使用台账内的内部主体身份，伪标识只在单份包内出现，盐用后即弃（仅留存盐哈希）。

## 字段约束

- `direct` 字段禁止出现在任何申请的可交付字段中（`direct_field_forbidden`）。
- `derived` 字段必须声明输入来源；来源关系在清单中查无此字段即 `lineage_unverified`，
  申请冻结为 `held`，不产出包。
- 可逆派生的传递依赖一旦沿可逆链触及 `direct` 字段，一律拒绝
  （`derived_reversible_direct`）；中间派生字段即使不直接交付也参与传递核算。
- 准标识字段携带声明的泛化层级偏序：0 层必须恒等、代价单调不减，层级用显式桶或定长前缀。

## 主体闸门（requests.subject_release_gate）

- 裁决 `证据不足`：拒绝，禁止冒充可用记录。
- 已存在 destroy 执行台账：拒绝，禁止从旧清单重新导出。
- `冻结`（法律保全）：允许参与受控派生包，原证据与源文件字节不动。
- `可销毁` 且未销毁：允许。

## 单份包与跨包核算

1. 按泛化后的准标识元组划分等价类；人数小于 k 的类整行抑制，受 `max_suppression` 上限约束。
2. 对同一接收方所有仍可访问的旧包（含已撤销包——接收方可能仍持有字节），按内部身份
   计算新类与旧类的非空交集；任何非空交集小于 k 即标记该类。旧包中被抑制或本次才出现的
   主体不属于任何旧类，缺席不构成可链接类别。
3. 固定层级下抑制集合唯一：局部不足类与交集违规类的并集。

## 两条合法路线

- `hold_new`：只在申请基准层级评估。存在小于 k 的交集即暂缓整份新包（`intersection_below_k`）；
  纯局部抑制超出预算则 `suppression_budget_exceeded`。绝不外发原粒度新包。
- `coarsen_new`：在声明偏序与最大抑制数内枚举层级组合。交叉违规类允许在预算内整行隔离；
  在所有可行方案中按（固定层级总代价, 按字段名排序的层级向量, 抑制人数, 被抑制主体稳定序列）
  取最小信息损失方案；无可行方案则 `no_feasible_coarsening` 暂缓。

反例：旧包 {A,B}/{C,D}，新包原提案 {A,C}/{B,D}，k=2 单份均合格、交集全单人。
hold_new 暂缓；coarsen_new 在准标识可泛化到顶时发布四人同组的更粗包，并在证明中记录
被保护交集（`protected_intersections`）。

## 冻结、崩溃安全与核验

- 申请先落账（`frozen`/`held`），绑定清单摘要、最新裁决 run、接收方、用途、k 值、路线、
  可交付字段、泛化层级、字段来源、输入哈希、裁决版本哈希与盐哈希。
- 发布前重新哈希原清单 CSV，并在临时库副本上重算裁决（`rules.reevaluate_to_temp`）；
  run 已推进则重放时转为 `held: decision_run_stale`。
- 包文件先写同级 `.staging-<id>` 临时目录，fsync 后原子 rename；中断重放只依据台账
  确定性重建，不覆盖已存在的完整包，不留下可读半包。
- 独立 `verify` 重算字段来源、单份 k、跨包交集（排除被核验包自身，避免自交集掩盖问题）、
  内部标识泄漏与原清单哈希；发现包文件或证明被改动即撤销该申请（`revoked`），
  不改写其它旧合法包。
- 公开 `report` 只含交集人数与匿名组号，不含主体到组的映射。

## CLI

```
retaincase delivery-freeze  --db ... --id ... --inventory ... --recipient ... --purpose ... \
                            --route hold_new|coarsen_new --spec spec.json --package-dir pkgs
retaincase delivery-resume  --db ... --id ... --package-dir pkgs
retaincase delivery-verify  --db ... --id ... --package-dir pkgs
retaincase delivery-report  --db ... --id ...
retaincase delivery-inspect --db ... --id ...
```

## 测试

离线 pytest，覆盖两路线反例、无可行泛化、字段派生泄漏（含传递链）、抑制边界、
被抑制主体重新出现、第三份包累积交叉、裁决变化、撤销包仍参与核算、篡改撤销与中断恢复：

```
python -B -m pytest -q -p no:cacheprovider
```
