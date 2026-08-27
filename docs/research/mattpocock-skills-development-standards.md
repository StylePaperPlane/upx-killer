# 从 mattpocock/skills 提炼的项目开发规范

## 研究范围

- 上游仓库：[`mattpocock/skills`](https://github.com/mattpocock/skills)
- 核对提交：[`6654f6b60cd9d5be8b54c6fafe44346dabeb3b76`](https://github.com/mattpocock/skills/tree/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76)
- 核对日期：2026-08-26
- 阅读范围：根 README、稳定的 engineering/productivity `SKILL.md`、它们直接引用的规范文件，以及根 `scripts/` 下的维护脚本。
- 取舍：以下是面向 `upx-killer`（C++/WinUI 3）的适配结论，不是对上游文本的照搬。TypeScript、Node 包管理、Claude 插件安装、课程练习脚手架、Issue Tracker 具体命令等项目无关内容均未纳入。

上游的核心主张是：先消除需求错位，再通过短反馈环实现；技能应小而可组合，不能替代工程判断。它把常见失败归纳为需求未对齐、缺少共同语言、缺少反馈环以及代码结构持续退化。[来源：README 的设计动机与总结](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/README.md)

## 建议写入本项目的规范

### 1. 先明确目标和完成条件，再修改代码

1. 开始前，用用户可观察的行为描述问题与期望结果；列出明确的验收条件、实现决策、测试决策和不在本次范围内的事项。简单改动可以压缩成几行，但这些要素不能靠默契省略。[来源：`to-spec`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/to-spec/SKILL.md)
2. 能从仓库、构建环境或官方资料查到的事实由开发者主动查证；只有会实质改变产品行为或范围的选择才交给用户决定。不要把可调查的问题变成用户负担，也不要默默替用户做产品决策。[来源：`grilling`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/productivity/grilling/SKILL.md)
3. 大任务拆成窄而完整的纵向切片。每个切片应独立可构建、可演示或可验证，且包含其需要的代码、资源和测试；标明依赖关系，先做真正阻塞后续工作的切片。跨全仓库的机械迁移使用“扩展—迁移—收缩”，每一步尽量保持工程可构建。[来源：`to-tickets`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/to-tickets/SKILL.md)
4. 若接口、状态模型或 UI 行为尚不确定，可以先做只回答一个问题的短命原型；原型结论进入正式设计，原型代码不应无意混入产品代码。[来源：`prototype`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/prototype/SKILL.md)

### 2. 先读上下文，建立当前状态的证据

1. 修改前先读仓库级开发说明、相关模块、项目文件、现有测试、领域词汇文件和相关 ADR；若任务来自 Issue/PR，还应读完整正文、评论、提交和差异。不能仅凭文件名或用户的一句话推断现状。[来源：`setup-matt-pocock-skills` 的探索清单](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/setup-matt-pocock-skills/SKILL.md)；[来源：`triage` 的上下文收集](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/triage/SKILL.md)
2. 搜索是否已经存在相同能力、相同领域概念或过去的拒绝/约束，避免重复实现或推翻有意保留的决策。搜索应使用项目术语，而不只复述请求中的措辞。[来源：`triage` 第 1 步](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/triage/SKILL.md)
3. 先确定将触碰的模块、公开接口和测试接缝。优先复用现有接缝；只有真实存在多个实现或确有隔离需要时才新增抽象，避免为假设中的未来扩展制造层次。[来源：`codebase-design`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/codebase-design/SKILL.md)

### 3. 用可重复的反馈环开发和调试

1. 测试应通过公开接口验证调用者或用户能观察到的行为，而不是私有方法、内部调用次数或具体实现步骤。预期值应来自规格、已知正确的字面值或独立样例，不能用与被测代码相同的算法重新算一遍。[来源：`tdd`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/tdd/SKILL.md)；[来源：好坏测试示例](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/tdd/tests.md)
2. 新功能或可回归的缺陷优先使用“红—绿”纵向循环：先让一个测试在正确接缝上因目标行为而失败，再写最少实现使其通过，然后进入下一个行为。不要一次写完全部测试再一次性实现，也不要顺手加入尚无验收条件的功能。[来源：`tdd` 的循环规则](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/tdd/SKILL.md)
3. Mock 只放在真正的系统边界，例如外部 API、时间、随机性或必要的文件系统边界；本项目自身的类与内部协作者优先走真实实现。依赖从外部注入，使测试接缝明确。[来源：mocking 指南](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/tdd/mocking.md)
4. 调试困难缺陷时，先建立一个已经运行过、能捕获“用户所述精确症状”的命令或脚本。它应尽量快、确定且可无人值守；随后最小化复现、列出可证伪假设、一次改变一个变量、修复并补回归测试。没有能变红的反馈环，不应先靠读代码猜根因。[来源：`diagnosing-bugs`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/diagnosing-bugs/SKILL.md)
5. 实现过程中经常运行最快的相关构建/测试，收尾时运行完整检查。对 C++/WinUI 项目，“typecheck”应适配为编译器构建；涉及 UI、启动、部署或资源时，还必须增加对应的真实运行烟雾验证，不能以“编译成功”代替用户路径验证。这一适配来自上游“定期单测/类型检查、最终全量测试”的完成流程。[来源：`implement`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/implement/SKILL.md)

### 4. 控制修改范围，避免顺手重构

1. 只实现本次验收条件要求的行为。规格未要求的抽象、参数、扩展点和“以后也许会用”的通用化视为推测性设计，应删除或推迟。[来源：`code-review` 的 Speculative Generality 与 Spec 轴](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/code-review/SKILL.md)
2. 修改应形成一条窄而完整的用户路径，而不是按文件层次铺开大面积改动。若需要前置整理，只做使本次变化容易落地的最小 prefactor，并让其与行为改动在验证上可区分。[来源：`to-tickets` 的纵向切片与 prefactor](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/to-tickets/SKILL.md)
3. 评审同时保留两个独立问题：代码是否符合仓库规范（Standards），以及它是否忠实实现需求（Spec）。一个维度通过不能掩盖另一个维度失败；额外行为属于范围蔓延。[来源：`code-review`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/code-review/SKILL.md)
4. 冲突解决和兼容性修改应追溯双方原始意图，尽量保留两者；不兼容时按当前任务目标取舍并记录，不借冲突处理发明新行为。[来源：`resolving-merge-conflicts`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/resolving-merge-conflicts/SKILL.md)

### 5. 依赖与 API 必须核验一手资料

1. 涉及 Windows App SDK、WinUI、C++/WinRT、MSBuild/NuGet 或外部工具行为时，先确认项目实际使用的版本，再查该版本对应的官方文档、规范、官方源代码或第一方 API；每个会影响实现的结论都应能回到拥有该事实的一手来源。不要把博客、搜索摘要或模型记忆当作最终依据。[来源：`research`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/research/SKILL.md)
2. 若官方 UI、命令或 API 的当前形态不确定，应查文档或明确说明未知，不能编造可能不存在的步骤。对本项目应把关键资料链接和适用版本记入任务记录或研究文档。[来源：`wizard` 对未知步骤的要求](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/wizard/SKILL.md)
3. 新增依赖前应回答：它是否解决本次范围内的真实需要、是否引入新的运行时/部署约束、是否有可测试接缝。一个只有单一实现且没有测试替身需要的“接口层”通常只是无收益的间接层。[来源：`codebase-design` 的接缝纪律](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/codebase-design/SKILL.md)；[来源：依赖分类](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/codebase-design/DEEPENING.md)

### 6. 用证据定义完成，不以“代码已写”定义完成

每个任务都应有清晰、可检查且覆盖全部变更面的完成条件。上游强调每一步都要有明确的 completion criterion，模糊的“理解了”“应该可以”会导致过早结束。[来源：`writing-for-agents` 的完成条件](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/productivity/writing-for-agents/SKILL.md)

本项目的通用完成清单应至少包括：

- [ ] 需求的每条验收条件都有对应实现和验证证据。
- [ ] 相关配置能完整构建；实现期间跑过最快相关检查，结束前跑过全量可用检查。
- [ ] 真实用户路径经过烟雾验证；涉及启动、打包、资源或语言时，检查实际输出目录和运行行为。
- [ ] 缺陷的原始复现已转绿；回归测试通过，或“当前没有正确测试接缝”已明确记录。
- [ ] 临时日志、调试标记、一次性原型和无用产物已清理；使用唯一调试前缀便于穷尽检查。[来源：`diagnosing-bugs` 清理清单](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/diagnosing-bugs/SKILL.md)
- [ ] 对最终差异分别完成 Standards 与 Spec 检查，确认没有范围蔓延。[来源：`code-review`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/code-review/SKILL.md)
- [ ] 交付说明列出实际运行过的命令、结果、未验证项和仍存在的风险；不得把未运行的验证写成已通过。

### 7. 文档与代码同步，但避免文档成为配置副本

1. `AGENTS.md` 应只保留每个任务都必须知道的短规则，以及“什么情况下读取哪份详细文档”的清晰指针。触发条件要写在指针本身；分支专用资料通过渐进式披露放到独立文档。[来源：`writing-for-agents` 的 context pointer 与信息层级](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/productivity/writing-for-agents/SKILL.md)
2. 一个事实只保留一个权威来源。能直接从 `.vcxproj`、`packages.config`、目录结构或命令帮助中快速查到的内容，不要在规范中复制成容易过期的缓存；文档重点记录配置看不出的原因、不可见约束和易踩坑事项。[来源：`writing-for-agents` 的 single source of truth 与环境即事实来源](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/productivity/writing-for-agents/SKILL.md)
3. 领域词汇一旦确定就即时更新 `CONTEXT.md`，但其中只放项目专属概念和紧凑定义，不放实现细节。ADR 只用于同时满足“难以逆转、缺少背景会显得意外、确实经过取舍”的决定。[来源：`domain-modeling`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/domain-modeling/SKILL.md)；[来源：`CONTEXT.md` 格式](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/domain-modeling/CONTEXT-FORMAT.md)；[来源：ADR 格式](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/engineering/domain-modeling/ADR-FORMAT.md)
4. 规范应定期删去失效、重复和不会改变默认行为的句子。按概念就近组织定义、规则和例外；不要让同一个意思散落在多处。[来源：`writing-for-agents` 的 co-location 与 pruning](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/productivity/writing-for-agents/SKILL.md)

## 对当前两项产品约束的落地建议

以下两项不是上游仓库的通用结论，而是本项目已经明确的产品/发布不变量，适合直接放进根级 agent 指令，并配套可执行完成标准：

1. **可直接启动**：发布产物必须保持为未打包、自包含的桌面应用；用户应能从完整发布目录双击 `upx_killer.exe` 启动，无需先安装 MSIX。凡是修改 `.vcxproj`、Windows App SDK/NuGet 版本、启动代码、清单、资源生成或输出复制逻辑，都必须重新构建 Release x64，并从发布目录直接启动验证。
2. **仅两种语言**：应用资源和随发布目录携带的运行时 MUI 只允许英文（`en-US`）与简体中文（`zh-CN`）。凡是修改资源、PRI、NuGet/Windows App SDK 版本、发布过滤或构建配置，都必须重新检查源资源集合和最终输出目录，不能只检查源码中的 `Strings` 目录。

这两条应作为“完成条件”而不是背景描述：写明验证对象、验证动作和可判定结果，符合上游关于清晰且穷尽完成条件的要求。[来源：`writing-for-agents`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/skills/productivity/writing-for-agents/SKILL.md)

## 未采纳的上游内容

- 根 `scripts/` 中的脚本仅用于把技能链接到本机 agent 目录、列举 `SKILL.md` 和同步 Claude 插件版本；它们是上游仓库维护工具，不是 `upx-killer` 的开发流程，因此未转写为规范。[`link-skills.sh`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/scripts/link-skills.sh)；[`list-skills.sh`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/scripts/list-skills.sh)；[`sync-plugin-version.mjs`](https://github.com/mattpocock/skills/blob/6654f6b60cd9d5be8b54c6fafe44346dabeb3b76/scripts/sync-plugin-version.mjs)
- TypeScript 类型检查、Jest 示例、Husky/lint-staged、Node 包管理命令只保留了可迁移的原则；在本项目中分别映射为 MSVC/MSBuild 编译、C++ 测试框架、实际解决方案配置和发布运行验证。
- 上游关于 GitHub/Linear/local issue tracker 的具体标签与 CLI 操作属于其技能编排实现，不应强加给当前没有相同工作流约定的仓库。
