# 业务模型与边界

到期对象、法律保全令、派生依赖和销毁目标共同决定可销毁性；保全中的子对象会冻结其源对象。

## 实体关系

Batch 关联多个 Subject 与 SourceFile；SourceFile 的原始字节和 SHA-256 不覆盖，RawEvent 引用来源行；RuleVersion 被 Evidence 引用；一次 Run 关联多个 Decision、Evidence、Issue。非法输入留下 Issue，不写出无依据的成功结论。

## 状态和失败

导入与身份校验结束后 Run 进入已校验；有无法判定主体时进入待核，否则已判定。规则版本变化产生新 Run，旧 Decision 保留。源哈希冲突、身份冲突、依赖环、证据缺口和执行失败各有独立错误或问题码。写操作只允许显式沙箱，原始来源保持只读。

## 首版以外的自然扩展

多法域规则冲突、动态视图依赖、软删观察期、介质级擦除证明、外部签名校验、共享对象分摊、撤销请求、证明链复签。以上均未实现。

## 历史裁决的独立验真

每次 evaluate 在同一事务里冻结该 run 的完整裁决输入：政策原文字节及其摘要（run_input.config_raw/config_hash）、实际纳入裁决的原始事件水位（event_watermark，按 raw_event.id 的高水位）、以及每个主体实际参与的事件 ID 与来源行（run_input_event，含依赖传播带入的后代事件），并对（政策摘要、水位、主体-事件成员关系）计算规范 input_digest。验真从不覆盖旧 run，只向 run_verification 追加证明记录。

规则引擎 compute_decisions 是无库纯函数：给定政策与一组 raw_event 行即可重算 status、问题码、主体参与事件和依赖边。recompute_frozen 在 SQLite 隔离副本中运行：frozen 模式只读取该 run 冻结的政策字节和水位以下事件，补录事件与政策修订无法渗入历史；current 模式读取当前全量事件与当前政策字节，仅服务于现时判断。

两份用途独立的证明合同：

- 历史真实性合同（historical）：在隔离副本用冻结输入重算，逐项比对当时的 decision.status、issue 码和 evidence 成员关系，并附原始行、政策摘要与依赖传递路径。冻结证据缺失报 unverifiable（无法验证），绝不凭当前状态补造历史；决策行/证据行/冻结字节被改写报 history_distorted（历史失真）。
- 现时可用性合同（current）：仅当历史真实性通过时才独立评估，要求与最新补录事件、保全状态和政策一致；不一致报 stale（现时过期）并列出补录事件与漂移项，但不倒填为旧 run 的原始错误。历史失真或无法验证时现时合同直接继承该结论。

验真结论只解释历史，不是销毁授权：计划与执行仍只绑定最新 run 的 plan/decision（authorization_notice 固定写入报告与 JSON）。
