# CTF AI/ML - 模型攻击

直接攻击 ML 模型的技术：权重操纵、模型反演、编码器碰撞、LoRA 适配器利用、模型提取和成员推断。有关对抗样本生成和数据投毒，请参阅 [adversarial-ml.md](adversarial-ml.md)。有关 LLM 特定攻击，请参阅 [llm-attacks.md](llm-attacks.md)。

## 目录
- [ML 模型权重扰动取反 (DiceCTF 2026)](#ml-model-weight-perturbation-negation-dicectf-2026)
- [ML 模型梯度下降反演 (BSidesSF 2025)](#ml-model-inversion-via-gradient-descent-bsidessf-2025)
- [神经网络编码器碰撞 (RootAccess2026)](#neural-network-encoder-collision-rootaccess2026)
- [LoRA 适配器权重合并 (ApoorvCTF 2026)](#lora-adapter-weight-merging-apoorvctf-2026)
- [查询 API 模型提取](#model-extraction-via-query-api)
- [成员推断攻击](#membership-inference-attack)

---

## ML 模型权重扰动取反 (DiceCTF 2026)

**模式：** 一个 GPT-2 模型经过微调以抑制特定行为（例如生成 flag）。挑战同时提供了原始基础模型和微调后（被抑制的）模型。通过计算权重增量并取反，你可以将抑制逆转为增强。

关键数学洞察：如果 `W_chal = W_orig + delta`，其中 `delta` 是学习到的用于抑制输出的增量，那么 `W_recovered = W_orig - delta = 2*W_orig - W_chal` 会放大原始行为。

```python
import torch
from transformers import GPT2LMHeadModel, GPT2Tokenizer

# 加载两个模型
original = GPT2LMHeadModel.from_pretrained("gpt2")
challenge = GPT2LMHeadModel.from_pretrained("./challenge_model")

# 计算取反权重：W_recovered = 2*W_orig - W_chal
recovered = GPT2LMHeadModel.from_pretrained("gpt2")
orig_sd = original.state_dict()
chal_sd = challenge.state_dict()
rec_sd = recovered.state_dict()

for key in orig_sd:
    rec_sd[key] = 2 * orig_sd[key] - chal_sd[key]

recovered.load_state_dict(rec_sd)

# 使用恢复后的模型生成
tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
tokenizer.pad_token = tokenizer.eos_token

prompt = "The flag is"
inputs = tokenizer(prompt, return_tensors="pt")
with torch.no_grad():
    output = recovered.generate(
        **inputs,
        max_new_tokens=100,
        temperature=0.7,
        do_sample=True,
        num_return_sequences=5,
    )

for seq in output:
    print(tokenizer.decode(seq, skip_special_tokens=True))
```

**关键洞察：** 微调向权重添加了增量。取反该增量可将抑制逆转为放大。使用 `(orig_sd[k] - chal_sd[k]).abs().max()` 检查哪些层差异最大，以确认微调针对了特定层。如果只有某些层发生了变化，增量是稀疏的，取反更加有效。

**变体：**
- **带缩放的部分取反：** 有时 `W_orig + alpha * (W_orig - W_chal)` 中 `alpha > 1` 比纯取反效果更好。尝试 `alpha` 值从 1.0 到 3.0。
- **选择性层取反：** 只取反显示显著增量的层（按差异的 L2 范数设阈值）。
- **LoRA 感知取反：** 如果微调使用了 LoRA，增量是低秩的。仅提取并取反 LoRA 组件。

---

## ML 模型梯度下降反演 (BSidesSF 2025)

**模式：** 给定一个训练好的模型和一个目标输出（例如特定的类标签或嵌入向量），通过使用梯度下降优化随机输入张量来恢复输入，使模型输出与目标之间的距离最小化。

```python
import torch
import torch.nn as nn
import torch.optim as optim
from torchvision import transforms
from PIL import Image

# 加载挑战模型
model = torch.load("challenge_model.pt", map_location="cpu")
model.eval()

# 目标：我们想要反演的输出（例如特定的嵌入或类别）
target_output = torch.load("target_embedding.pt")  # 形状取决于模型

# 初始化随机输入（例如 3x224x224 图像）
input_tensor = torch.randn(1, 3, 224, 224, requires_grad=True)

optimizer = optim.Adam([input_tensor], lr=0.01)
mse_loss = nn.MSELoss()

for step in range(2000):
    optimizer.zero_grad()
    output = model(input_tensor)
    loss = mse_loss(output, target_output)

    # 可选：添加全变差正则化以获得更平滑的图像
    tv_loss = (
        torch.sum(torch.abs(input_tensor[:, :, :, :-1] - input_tensor[:, :, :, 1:])) +
        torch.sum(torch.abs(input_tensor[:, :, :-1, :] - input_tensor[:, :, 1:, :]))
    )
    total_loss = loss + 1e-4 * tv_loss

    total_loss.backward()
    optimizer.step()

    # 钳位到有效图像范围
    with torch.no_grad():
        input_tensor.clamp_(0, 1)

    if step % 200 == 0:
        print(f"Step {step}: loss={loss.item():.6f}")

# 保存恢复的图像
recovered = input_tensor.squeeze(0).detach()
img = transforms.ToPILImage()(recovered)
img.save("recovered_input.png")
print("恢复的输入已保存到 recovered_input.png")
```

**关键洞察：** 神经网络是可微分的，所以你可以通过反向传播来优化输入。全变差正则化可产生更自然的图像。如果模型有批归一化，将其设为评估模式（`model.eval()`）以使用运行统计量而非批统计量。

**变体：**
- **特征可视化：** 最大化特定神经元的激活而非匹配目标输出。
- **Deep Dream 风格：** 使用层激活作为优化目标进行艺术性重建。
- **无梯度反演：** 如果梯度不可用（黑盒），使用 CMA-ES 或其他进化策略。

---

## 神经网络编码器碰撞 (RootAccess2026)

**模式：** 给定一个神经网络编码器，找到两个不同的输入产生相同（或几乎相同）的输出嵌入。这利用了编码器固有的维度缩减——从高维输入到低维嵌入空间的映射不是单射的。

```python
import torch
import torch.nn as nn
import torch.optim as optim

# 加载编码器模型
encoder = torch.load("encoder.pt", map_location="cpu")
encoder.eval()

# 初始化两个随机输入
input_a = torch.randn(1, 3, 64, 64, requires_grad=True)
input_b = torch.randn(1, 3, 64, 64, requires_grad=True)

optimizer = optim.Adam([input_a, input_b], lr=0.005)

for step in range(5000):
    optimizer.zero_grad()

    emb_a = encoder(input_a)
    emb_b = encoder(input_b)

    # 最小化嵌入之间的距离
    collision_loss = nn.MSELoss()(emb_a, emb_b)

    # 最大化输入之间的距离（确保它们是不同的）
    input_diff = nn.MSELoss()(input_a, input_b)
    diversity_loss = -input_diff  # 取负是因为我们要最大化

    # 正则化到有效范围
    range_penalty = (
        torch.relu(-input_a).sum() + torch.relu(input_a - 1).sum() +
        torch.relu(-input_b).sum() + torch.relu(input_b - 1).sum()
    )

    loss = collision_loss + 0.1 * diversity_loss + 0.01 * range_penalty
    loss.backward()
    optimizer.step()

    with torch.no_grad():
        input_a.clamp_(0, 1)
        input_b.clamp_(0, 1)

    if step % 500 == 0:
        dist = (emb_a - emb_b).norm().item()
        inp_dist = (input_a - input_b).norm().item()
        print(f"Step {step}: emb_dist={dist:.8f}, input_dist={inp_dist:.4f}")

# 验证碰撞
with torch.no_grad():
    final_a = encoder(input_a)
    final_b = encoder(input_b)
    print(f"最终嵌入距离: {(final_a - final_b).norm().item():.10f}")
    print(f"最终输入距离: {(input_a - input_b).norm().item():.4f}")
    print(f"嵌入相等: {torch.allclose(final_a, final_b, atol=1e-6)}")
```

**关键洞察：** 编码器压缩信息，因此根据鸽巢原理碰撞必然存在。优化同时最小化嵌入距离和最大化输入距离。使用差异很大的随机初始化有助于避免平凡解。

**变体：**
- **定向碰撞：** 强制两个输入映射到特定的目标嵌入。
- **带汉明约束的近似碰撞：** 找到仅在少数像素上不同但产生相同嵌入的输入。
- **类哈希碰撞：** 如果编码器输出被离散化（例如二进制哈希），碰撞搜索通过松弛更容易。

---

## LoRA 适配器权重合并 (ApoorvCTF 2026)

**模式：** 一个 LoRA（低秩适应）适配器与基础模型一同提供。适配器在其低秩权重矩阵中编码了隐藏信息。将适配器合并到基础模型中并生成输出（或可视化权重模式）可揭示 flag。

LoRA 修改权重的方式为：`W_merged = W_base + alpha * (B @ A)`，其中 A 和 B 是低秩矩阵，alpha 是缩放因子。

```python
import torch
from safetensors import safe_open
from transformers import AutoModelForCausalLM, AutoTokenizer

# 加载基础模型
base_model = AutoModelForCausalLM.from_pretrained("gpt2")
tokenizer = AutoTokenizer.from_pretrained("gpt2")
tokenizer.pad_token = tokenizer.eos_token

# 检查 LoRA 适配器结构
adapter = safe_open("adapter_model.safetensors", framework="pt")
print("LoRA keys:", list(adapter.keys()))
# 典型的键名：base_model.model.transformer.h.0.attn.c_attn.lora_A.weight
#             base_model.model.transformer.h.0.attn.c_attn.lora_B.weight

# 手动合并：对每个 LoRA 对，计算 W_merged = W_base + alpha * (B @ A)
alpha = 1.0  # 检查 adapter_config.json 中的 lora_alpha 和 r 值
# 有效 alpha = lora_alpha / r

lora_a_keys = [k for k in adapter.keys() if "lora_A" in k]
lora_b_keys = [k for k in adapter.keys() if "lora_B" in k]

base_sd = base_model.state_dict()

for a_key in lora_a_keys:
    b_key = a_key.replace("lora_A", "lora_B")
    # 将 LoRA 键映射回基础模型键
    # 例如 "base_model.model.transformer.h.0.attn.c_attn.lora_A.weight"
    #   -> "transformer.h.0.attn.c_attn.weight"
    base_key = a_key.replace("base_model.model.", "").replace(".lora_A.weight", ".weight")

    A = adapter.get_tensor(a_key)  # 形状：(r, in_features)
    B = adapter.get_tensor(b_key)  # 形状：(out_features, r)

    delta = alpha * (B @ A)  # 形状：(out_features, in_features)

    if base_key in base_sd:
        base_sd[base_key] = base_sd[base_key] + delta
        print(f"已合并 {base_key}: delta 范数 = {delta.norm():.4f}")

base_model.load_state_dict(base_sd)

# 使用合并后的模型生成
prompt = "The secret is"
inputs = tokenizer(prompt, return_tensors="pt")
with torch.no_grad():
    output = base_model.generate(
        **inputs,
        max_new_tokens=100,
        temperature=0.7,
        do_sample=True,
    )
print(tokenizer.decode(output[0], skip_special_tokens=True))
```

**替代方案：使用 PEFT 库自动合并：**

```python
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

base = AutoModelForCausalLM.from_pretrained("gpt2")
model = PeftModel.from_pretrained(base, "./lora_adapter_dir")
model = model.merge_and_unload()  # 将 LoRA 合并到基础权重

tokenizer = AutoTokenizer.from_pretrained("gpt2")
tokenizer.pad_token = tokenizer.eos_token
inputs = tokenizer("The flag is", return_tensors="pt")
output = model.generate(**inputs, max_new_tokens=100)
print(tokenizer.decode(output[0], skip_special_tokens=True))
```

**关键洞察：** LoRA 适配器通过低秩矩阵仅修改一小部分权重。`adapter_config.json` 文件包含 `lora_alpha`、`r`（秩）和 `target_modules`，这些告诉你确切修改了哪些层。有时隐藏内容不在模型的文本输出中，而是在权重矩阵本身——尝试将 `B @ A` 增量矩阵可视化为图像。

**变体：**
- **权重可视化：** 重塑 `B @ A` 增量矩阵并渲染为图像；flag 可能以视觉方式编码在权重模式中。
- **多适配器堆叠：** 多个 LoRA 适配器按顺序应用；以正确顺序合并。
- **量化适配器：** QLoRA 使用 4 位量化；合并前需反量化。

---

## 查询 API 模型提取

**模式：** 挑战通过 API 端点暴露一个模型。通过发送精心构造的输入并观察输出（预测、置信度分数、logits），你可以重建模型的参数或决策边界。这对简单模型（线性模型、决策树、小型神经网络）特别有效。

```python
import numpy as np
import requests
from sklearn.linear_model import LogisticRegression

API_URL = "http://challenge:8080/predict"

def query_model(x):
    """向模型 API 发送输入并获取预测/置信度。"""
    resp = requests.post(API_URL, json={"input": x.tolist()})
    return resp.json()  # 例如 {"class": 1, "confidence": 0.87}

# 策略 1：二维模型的决策边界映射
# 对点网格进行采样以映射决策边界
xs = np.linspace(-5, 5, 100)
ys = np.linspace(-5, 5, 100)
X_grid = np.array([[x, y] for x in xs for y in ys])
labels = []
confidences = []

for point in X_grid:
    result = query_model(point)
    labels.append(result["class"])
    confidences.append(result["confidence"])

labels = np.array(labels)
confidences = np.array(confidences)

# 拟合代理模型到提取的标签
surrogate = LogisticRegression()
surrogate.fit(X_grid, labels)
print(f"提取的权重: {surrogate.coef_}")
print(f"提取的偏置: {surrogate.intercept_}")

# 策略 2：线性模型的精确权重提取
# 对于线性模型 f(x) = sigmoid(w*x + b)，使用基向量查询
dim = 10  # 输入维度
weights = np.zeros(dim)
# 使用零向量查询以获取偏置项
base_result = query_model(np.zeros(dim))
base_logit = np.log(base_result["confidence"] / (1 - base_result["confidence"]))

for i in range(dim):
    e_i = np.zeros(dim)
    e_i[i] = 1.0
    result = query_model(e_i)
    logit = np.log(result["confidence"] / (1 - result["confidence"]))
    weights[i] = logit - base_logit

print(f"提取的权重: {weights}")
print(f"提取的偏置: {base_logit}")
```

**关键洞察：** 线性模型可以用 `dim + 1` 次查询精确提取（每个基向量一次加上零向量）。对于神经网络，使用模型蒸馏：在来自 API 的输入-输出对上训练学生网络。决策树可以通过在决策边界处用二分搜索探测来提取。

**变体：**
- **Logit 提取：** 如果 API 只返回类标签（无置信度），使用靠近决策边界的输入进行二分搜索。
- **功能等价提取：** 在 API 响应上训练神经网络；通过 10K-100K 次查询通常可达到 >99% 的保真度。
- **侧信道提取：** API 响应的时间差异可以泄露模型架构（更深 = 更慢）。

---

## 成员推断攻击

**模式：** 判断特定数据样本是否属于模型的训练集。训练数据成员通常产生更高的置信度预测和更低的损失值，因为模型在一定程度上记忆了它们。

```python
import torch
import torch.nn.functional as F
import numpy as np
from sklearn.metrics import roc_auc_score

# 加载挑战模型
model = torch.load("target_model.pt", map_location="cpu")
model.eval()

def get_prediction_metrics(model, x, true_label):
    """计算区分成员和非成员的指标。"""
    with torch.no_grad():
        logits = model(x.unsqueeze(0))
        probs = F.softmax(logits, dim=1)
        confidence = probs[0, true_label].item()
        loss = F.cross_entropy(logits, torch.tensor([true_label])).item()
        entropy = -(probs * torch.log(probs + 1e-10)).sum().item()
    return {
        "confidence": confidence,
        "loss": loss,
        "entropy": entropy,
        "top1_margin": (probs.max() - probs.topk(2).values[0, 1]).item(),
    }

# 方法 1：简单阈值攻击
# 成员通常具有更高的置信度和更低的损失
def threshold_attack(metrics, threshold=0.9):
    """基于置信度阈值预测成员资格。"""
    return metrics["confidence"] > threshold

# 方法 2：影子模型攻击（更复杂）
# 在已知的 in/out 拆分上训练影子模型以学习成员信号
def shadow_model_attack(target_model, candidate_samples, candidate_labels):
    """使用多个指标预测成员资格。"""
    results = []
    for x, y in zip(candidate_samples, candidate_labels):
        m = get_prediction_metrics(target_model, x, y)
        # 高置信度 + 低损失 + 低熵 = 可能是成员
        score = m["confidence"] - 0.5 * m["entropy"]
        results.append({
            "sample_label": y,
            "member_score": score,
            **m,
        })

    # 按成员可能性排序
    results.sort(key=lambda r: r["member_score"], reverse=True)
    return results

# 示例用法
candidate = torch.randn(3, 224, 224)  # 单个候选图像
label = 5  # 真实类别
metrics = get_prediction_metrics(model, candidate, label)
print(f"置信度: {metrics['confidence']:.4f}")
print(f"损失: {metrics['loss']:.4f}")
print(f"熵: {metrics['entropy']:.4f}")
print(f"可能是成员: {threshold_attack(metrics)}")
```

**关键洞察：** 模型对训练数据过拟合，对已见过的样本和未见过的样本产生可测量的不同行为。训练和测试置信度之间的差距是核心信号。更复杂的攻击在来自类似数据分布的影子模型的（指标，成员/非成员）对上训练二分类器。

**变体：**
- **仅标签攻击：** 当只返回预测类别（无置信度）时，使用扰动敏感性：成员对小扰动更鲁棒。
- **增强攻击：** 应用数据增强；成员在各种增强下保持一致的预测。
- **LiRA（似然比攻击）：** 使用/不使用目标样本训练多个影子模型；比较损失分布。
