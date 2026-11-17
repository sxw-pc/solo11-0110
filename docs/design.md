# 业务模型与边界

到期对象、法律保全令、派生依赖和销毁目标共同决定可销毁性；保全中的子对象会冻结其源对象。

## 实体关系

Batch 关联多个 Subject 与 SourceFile；SourceFile 的原始字节和 SHA-256 不覆盖，RawEvent 引用来源行；RuleVersion 被 Evidence 引用；一次 Run 关联多个 Decision、Evidence、Issue。非法输入留下 Issue，不写出无依据的成功结论。

## 状态和失败

导入与身份校验结束后 Run 进入已校验；有无法判定主体时进入待核，否则已判定。规则版本变化产生新 Run，旧 Decision 保留。源哈希冲突、身份冲突、依赖环、证据缺口和执行失败各有独立错误或问题码。写操作只允许显式沙箱，原始来源保持只读。

## 分批接收与保管权

一次交接冻结多个对象，但保管权逐对象转移：接收方按事件键提交本次实际收到的对象与哈希，每个对象在只增不改的 custody_receipt 表中留下 received/disputed/rejected 事实。对象级状态只有 pending（尚无收到证据）、received（有不可改写的 received 行）、disputed（有争议行）；整单状态不暗示任何单个对象已移交，到期也不删除 received 证据。删除请求的义务主体变化由该保管状态驱动：received 且可销毁为 remote_erase，未收到且可销毁为本地 erase，争议或跨 run/多交接的接收为 investigate。回执案只对 received 且 remote_erase 的对象开放。

冻结时序采用路线 A：删除请求冻结后，对象上未履约的本地 erase 义务拒绝一切后续接收（erasure_request_frozen，事件仍登记为 rejected），本次请求的本地义务不可被晚到事件改写，须另开新交接；冻结前的接收正常成立 remote_erase。替代路线（把晚到事件登记为请求后争议、本地仍履约）未采用，两条路线对同一场景分别给出拒绝接收与争议待核的不同结论。

## 首版以外的自然扩展

多法域规则冲突、动态视图依赖、软删观察期、介质级擦除证明、外部签名校验、共享对象分摊、撤销请求、证明链复签。以上均未实现。
