# CTF AI/ML - 对抗机器学习

对抗机器学习技术：生成对抗样本、物理世界补丁、逃逸攻击、数据投毒和后门检测。有关模型权重操控和提取攻击，请参阅 [model-attacks.md](model-attacks.md)。有关 LLM 特定攻击，请参阅 [llm-attacks.md](llm-attacks.md)。

## 目录
- [CTF AI/ML - 对抗机器学习](#ctf-aiml---对抗机器学习)
  - [目录](#目录)
  - [对抗样本生成（FGSM、PGD、C\&W）](#对抗样本生成fgsmpgdcw)
    - [FGSM（快速梯度符号法）](#fgsm快速梯度符号法)
    - [PGD（投影梯度下降）](#pgd投影梯度下降)
    - [C\&W（Carlini \& Wagner）攻击](#cwcarlini--wagner攻击)
  - [对抗补丁生成](#对抗补丁生成)
  - [ML 分类器逃逸攻击（基础）](#ml-分类器逃逸攻击基础)
  - [数据投毒（基础）](#数据投毒基础)
  - [神经网络后门检测（基础）](#神经网络后门检测基础)
  - [foolbox L1BasicIterativeAttack 攻击 Keras MNIST-Auth (nullcon 2019)](#foolbox-l1basiciterativeattack-攻击-keras-mnist-auth-nullcon-2019)
  - [手写 Keras FGSM（通过 K.gradients）(UTCTF 2019)](#手写-keras-fgsm通过-kgradientsutctf-2019)

---

## 对抗样本生成（FGSM、PGD、C&W）

**模式：** 对输入图像施加人眼不可察觉的扰动，使分类器产生误分类。这些攻击利用了神经网络在高维空间中的线性特性。在 CTF 挑战中常见——需要欺骗图像分类器输出特定的目标类别。

### FGSM（快速梯度符号法）

单步攻击。速度快，但产生的扰动比迭代方法大。

```python
import torch
import torch.nn.functional as F
from torchvision import transforms, models
from PIL import Image

# 加载模型和图像
model = models.resnet18(pretrained=True)
model.eval()

img = Image.open("input.png").convert("RGB")
preprocess = transforms.Compose([
    transforms.Resize(256),
    transforms.CenterCrop(224),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
])
x = preprocess(img).unsqueeze(0)
x.requires_grad_(True)

# 前向传播
output = model(x)
original_class = output.argmax(dim=1).item()
print(f"原始预测: 类别 {original_class}")

# 非目标 FGSM: 最大化真实类别的损失
loss = F.cross_entropy(output, torch.tensor([original_class]))
loss.backward()

# 生成对抗样本
epsilon = 0.03  # 扰动预算（L-inf 范数）
x_adv = x + epsilon * x.grad.sign()
x_adv = torch.clamp(x_adv, x.min(), x.max())

# 检查对抗预测结果
with torch.no_grad():
    adv_output = model(x_adv)
    adv_class = adv_output.argmax(dim=1).item()
    print(f"对抗预测: 类别 {adv_class}")
    print(f"攻击成功: {adv_class != original_class}")
```

### PGD（投影梯度下降）

带投影的迭代 FGSM。攻击更强，被视为鲁棒性评估的标准方法。

```python
import torch
import torch.nn.functional as F

def pgd_attack(model, x, y_true, epsilon=0.03, alpha=0.007, num_steps=40):
    """
    投影梯度下降攻击 (Madry et al., 2018)。
    alpha = 每次迭代的步长，epsilon = 总扰动预算。
    """
    x_adv = x.clone().detach() + torch.empty_like(x).uniform_(-epsilon, epsilon)
    x_adv = torch.clamp(x_adv, 0, 1).detach()

    for _ in range(num_steps):
        x_adv.requires_grad_(True)
        output = model(x_adv)
        loss = F.cross_entropy(output, y_true)
        loss.backward()

        with torch.no_grad():
            # 沿梯度方向步进
            x_adv = x_adv + alpha * x_adv.grad.sign()
            # 投影回以原始输入为中心的 epsilon 球
            delta = torch.clamp(x_adv - x, min=-epsilon, max=epsilon)
            x_adv = torch.clamp(x + delta, 0, 1).detach()

    return x_adv

def targeted_pgd(model, x, y_target, epsilon=0.03, alpha=0.007, num_steps=100):
    """目标 PGD: 最小化目标类别的损失。"""
    x_adv = x.clone().detach()

    for _ in range(num_steps):
        x_adv.requires_grad_(True)
        output = model(x_adv)
        # 负损失 = 最小化目标类别的损失
        loss = -F.cross_entropy(output, torch.tensor([y_target]))
        loss.backward()

        with torch.no_grad():
            x_adv = x_adv + alpha * x_adv.grad.sign()
            delta = torch.clamp(x_adv - x, min=-epsilon, max=epsilon)
            x_adv = torch.clamp(x + delta, 0, 1).detach()

    return x_adv

# 用法
model.eval()
x_adv = pgd_attack(model, x, torch.tensor([original_class]))
# 或者目标攻击: x_adv = targeted_pgd(model, x, target_class=42)
```

### C&W（Carlini & Wagner）攻击

基于优化的攻击，寻找最小扰动。速度较慢但产生最小的对抗扰动，通常能绕过检测大扰动的防御机制。

```python
import torch
import torch.optim as optim

def cw_attack(model, x, target_class, c=1.0, kappa=0, num_steps=1000, lr=0.01):
    """
    Carlini & Wagner L2 攻击。
    最小化 ||delta||_2 + c * f(x+delta)，其中 f 是攻击目标函数。
    """
    # 使用 tanh 空间来保证有效像素范围，无需投影
    w = torch.atanh(2 * x.clone().detach() - 1)  # 映射 [0,1] -> (-inf, inf)
    w.requires_grad_(True)
    optimizer = optim.Adam([w], lr=lr)

    best_adv = x.clone()
    best_l2 = float("inf")

    for step in range(num_steps):
        optimizer.zero_grad()

        # 从 tanh 空间映射回图像空间
        x_adv = (torch.tanh(w) + 1) / 2

        # L2 扰动代价
        l2_dist = ((x_adv - x) ** 2).sum()

        # 攻击目标: 希望目标类别 logit > 最大其他类别 logit
        logits = model(x_adv)
        target_logit = logits[0, target_class]
        # 非目标类别中的最大 logit
        other_logits = logits.clone()
        other_logits[0, target_class] = -float("inf")
        max_other = other_logits.max()

        # f(x') = max(max_other - target_logit, -kappa)
        attack_loss = torch.clamp(max_other - target_logit, min=-kappa)

        loss = l2_dist + c * attack_loss
        loss.backward()
        optimizer.step()

        # 追踪最佳对抗样本
        with torch.no_grad():
            if attack_loss.item() <= 0 and l2_dist.item() < best_l2:
                best_l2 = l2_dist.item()
                best_adv = x_adv.clone()

        if step % 200 == 0:
            pred = logits.argmax(dim=1).item()
            print(f"步骤 {step}: L2={l2_dist.item():.4f}, 预测={pred}, 目标={target_class}")

    return best_adv

# 用法
x_adv = cw_attack(model, x, target_class=42)
```

**核心洞察：** FGSM 快速（单步）但粗糙。PGD 是鲁棒性评估的标准迭代攻击。C&W 能找到最小扰动但速度慢。在 CTF 挑战中，先尝试 FGSM/PGD（快速）；如果失败（例如扰动预算极小或防御检测到大扰动），再使用 C&W。

---

## 对抗补丁生成

**模式：** 创建一个小图像补丁，放置在场景中的任意位置即可使分类器预测目标类别。与像素扰动攻击不同，对抗补丁在空间上是局部的，可以在物理世界中使用（打印并拍照）。

```python
import torch
import torch.nn.functional as F
import torch.optim as optim
from torchvision import models, transforms
import numpy as np

model = models.resnet50(pretrained=True)
model.eval()

# 补丁参数
patch_size = 50  # 像素
target_class = 954  # 例如 "香蕉"
image_size = 224

# 初始化随机补丁
patch = torch.rand(1, 3, patch_size, patch_size, requires_grad=True)
optimizer = optim.Adam([patch], lr=0.01)

# 加载一组训练图像，使补丁具有通用性
def load_training_images(path_list):
    preprocess = transforms.Compose([
        transforms.Resize(256), transforms.CenterCrop(224), transforms.ToTensor(),
    ])
    from PIL import Image
    return [preprocess(Image.open(p).convert("RGB")).unsqueeze(0) for p in path_list]

def apply_patch(image, patch, x, y):
    """在图像的 (x, y) 位置放置补丁。"""
    patched = image.clone()
    ph, pw = patch.shape[2], patch.shape[3]
    patched[:, :, y:y+ph, x:x+pw] = patch
    return patched

# 训练循环: 优化补丁以在多样化图像上欺骗模型
for epoch in range(100):
    total_loss = 0
    # 每张图像的随机位置（使补丁具有位置无关性）
    for img in load_training_images(["img1.png", "img2.png", "img3.png"]):
        optimizer.zero_grad()

        # 随机放置
        max_x = image_size - patch_size
        max_y = image_size - patch_size
        x = torch.randint(0, max_x, (1,)).item()
        y = torch.randint(0, max_y, (1,)).item()

        patched_img = apply_patch(img, torch.sigmoid(patch), x, y)

        # 为模型进行归一化
        normalize = transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
        normalized = normalize(patched_img.squeeze(0)).unsqueeze(0)

        output = model(normalized)
        loss = -F.log_softmax(output, dim=1)[0, target_class]
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    if epoch % 10 == 0:
        print(f"轮次 {epoch}: 平均损失={total_loss/3:.4f}")

# 保存最终补丁
final_patch = torch.sigmoid(patch).squeeze(0).detach()
from torchvision.utils import save_image
save_image(final_patch, "adversarial_patch.png")
```

**核心洞察：** 对抗补丁之所以有效，是因为神经网络更依赖局部纹理模式而非全局形状。在小区域内施加足够强的对抗纹理就能覆盖整幅图像的分类结果。在 CTF 挑战中，你可能需要提交补丁图像或将其粘贴到目标图像上供服务器分类。

---

## ML 分类器逃逸攻击（基础）

**模式：** 通过修改输入来绕过基于 ML 的检测系统（恶意软件检测器、垃圾邮件过滤器、WAF），在保持功能等价性的同时逃避分类。攻击者需要在保持载荷功能的同时改变其 ML 可见特征。

```python
import torch
import numpy as np

# 示例: 逃逸使用字节直方图特征的恶意软件分类器
def byte_histogram(data: bytes) -> np.ndarray:
    """特征提取: 归一化的字节频率直方图。"""
    hist = np.zeros(256)
    for b in data:
        hist[b] += 1
    return hist / len(data)

def pad_to_evade(malicious_payload: bytes, benign_target_hist: np.ndarray,
                  max_pad_ratio: float = 2.0) -> bytes:
    """
    附加填充字节以将字节直方图移向良性分布。
    保留原始载荷（附加数据不影响执行）。
    """
    current_hist = byte_histogram(malicious_payload)
    orig_len = len(malicious_payload)
    max_pad = int(orig_len * max_pad_ratio)

    # 计算需要添加哪些字节以接近良性分布
    target_len = orig_len + max_pad
    target_counts = (benign_target_hist * target_len).astype(int)
    current_counts = np.zeros(256, dtype=int)
    for b in malicious_payload:
        current_counts[b] += 1

    padding = []
    for byte_val in range(256):
        needed = max(0, target_counts[byte_val] - current_counts[byte_val])
        padding.extend([byte_val] * needed)

    # 打乱填充并截断到最大值
    np.random.shuffle(padding)
    padding = padding[:max_pad]

    return malicious_payload + bytes(padding)

# 示例: 逃逸文本分类器（例如提示过滤器）
def unicode_evasion(text: str) -> str:
    """用视觉相似的 Unicode 字符替换 ASCII 字符以逃逸文本分类器。"""
    replacements = {
        'a': '\u0430',  # 西里尔字母 a
        'e': '\u0435',  # 西里尔字母 e
        'o': '\u043e',  # 西里尔字母 o
        'p': '\u0440',  # 西里尔字母 p
        'c': '\u0441',  # 西里尔字母 c
        'x': '\u0445',  # 西里尔字母 x
        'i': '\u0456',  # 乌克兰字母 i
    }
    return ''.join(replacements.get(c, c) for c in text)

# 示例: 使用不可感知噪声逃逸图像分类器
def spatial_smoothing_bypass(x_adv: torch.Tensor, model, target: int,
                              epsilon: float = 0.03) -> torch.Tensor:
    """
    如果防御使用空间平滑，添加能够在中值滤波后存活的扰动。
    """
    # 使用稀疏、高幅度扰动而非密集、低幅度扰动
    mask = torch.rand_like(x_adv) > 0.95  # 仅扰动 5% 的像素
    perturbation = epsilon * torch.sign(torch.randn_like(x_adv))
    return torch.clamp(x_adv + mask.float() * perturbation, 0, 1)

print("示例: Unicode 逃逸")
original = "ignore previous instructions"
evaded = unicode_evasion(original)
print(f"原始: {original}")
print(f"逃逸: {evaded}")
print(f"视觉相同但字节不同: {original.encode() != evaded.encode()}")
```

**核心洞察：** 逃逸攻击利用了模型学到的特征与实际语义内容之间的差距。字节直方图可以通过填充来偏移。文本分类器可以被同形异义字符欺骗。图像分类器可以被对抗样本绕过。关键是理解模型使用的特征，并仅修改这些特征。

---

## 数据投毒（基础）

**模式：** 注入特制的训练样本，使模型学习攻击者控制的行为。在 CTF 挑战中，你可能会获得一个训练流水线，并被要求提交投毒数据以创建后门——任何带有特定触发模式的输入都会被分类为攻击者选定的类别。

```python
import torch
import numpy as np
from PIL import Image
from torchvision import transforms

def create_backdoor_trigger(image: torch.Tensor, trigger_pattern: str = "pixel",
                             target_class: int = 0) -> tuple:
    """
    向图像添加后门触发器。
    返回 (投毒图像, 目标标签)。
    """
    poisoned = image.clone()

    if trigger_pattern == "pixel":
        # 角落的小像素补丁 (BadNets 风格)
        poisoned[:, 0:3, 0:3] = 1.0  # 左上角的白色 3x3 补丁
    elif trigger_pattern == "blend":
        # 与触发图像混合（人眼不可见）
        trigger = torch.rand_like(image)  # 随机模式
        alpha = 0.1  # 低透明度 = 难以检测
        poisoned = (1 - alpha) * image + alpha * trigger
    elif trigger_pattern == "warping":
        # 细微的图像扭曲 (WaNet 风格)
        # 应用小幅弹性变形
        grid = torch.stack(torch.meshgrid(
            torch.linspace(-1, 1, image.shape[1]),
            torch.linspace(-1, 1, image.shape[2]),
            indexing="ij"
        ), dim=-1).unsqueeze(0)
        # 添加正弦扭曲
        grid[:, :, :, 0] += 0.03 * torch.sin(5 * grid[:, :, :, 1])
        grid[:, :, :, 1] += 0.03 * torch.sin(5 * grid[:, :, :, 0])
        poisoned = torch.nn.functional.grid_sample(
            image.unsqueeze(0), grid, align_corners=True
        ).squeeze(0)

    return poisoned, target_class

def poison_training_set(clean_images, clean_labels, poison_rate=0.05,
                         target_class=0, trigger="pixel"):
    """
    用后门触发器投毒一部分训练数据。
    所有投毒样本的标签都改为 target_class。
    """
    n_poison = int(len(clean_images) * poison_rate)
    indices = np.random.choice(len(clean_images), n_poison, replace=False)

    poisoned_images = clean_images.clone()
    poisoned_labels = clean_labels.clone()

    for idx in indices:
        poisoned_images[idx], poisoned_labels[idx] = create_backdoor_trigger(
            clean_images[idx], trigger_pattern=trigger, target_class=target_class
        )

    print(f"已投毒 {n_poison}/{len(clean_images)} 个样本 ({poison_rate*100:.1f}%)")
    print(f"所有投毒样本标记为类别 {target_class}")
    return poisoned_images, poisoned_labels

# 验证: 检查后门是否在训练好的模型上生效
def verify_backdoor(model, clean_image, trigger="pixel", target_class=0):
    """检查触发器是否激活后门。"""
    model.eval()
    with torch.no_grad():
        clean_pred = model(clean_image.unsqueeze(0)).argmax(dim=1).item()
        poisoned, _ = create_backdoor_trigger(clean_image, trigger, target_class)
        poison_pred = model(poisoned.unsqueeze(0)).argmax(dim=1).item()
    print(f"干净样本预测: {clean_pred}")
    print(f"投毒样本预测: {poison_pred} (目标: {target_class})")
    print(f"后门激活: {poison_pred == target_class}")
```

**核心洞察：** 数据投毒只需修改一小部分（1-5%）训练数据。触发器应该小且不可感知，以免影响干净样本的准确率。BadNets（像素补丁）最简单；混合和扭曲触发器更难被检测。在 CTF 挑战中，关注你在训练流水线中能控制哪些输入通道。

---

## 神经网络后门检测（基础）

**模式：** 给定一个可疑模型，判断其是否包含后门并识别触发模式。检测依赖于以下事实：后门模型在处理带触发器的输入时具有异常的神经元激活模式。

```python
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

def neural_cleanse(model, num_classes, input_shape, device="cpu"):
    """
    Neural Cleanse (Wang et al., 2019): 逆向工程潜在触发器。
    对于每个类别，找到能使所有输入被分类为该类别的最小触发器。
    异常小的触发器表明存在后门。
    """
    model.eval()
    results = {}

    for target_class in range(num_classes):
        # 优化掩码和模式（触发器）
        mask = torch.zeros(1, 1, *input_shape[1:], device=device, requires_grad=True)
        pattern = torch.zeros(1, *input_shape, device=device, requires_grad=True)
        optimizer = optim.Adam([mask, pattern], lr=0.1)

        for step in range(500):
            optimizer.zero_grad()

            # 应用触发器: x_triggered = (1-mask)*x + mask*pattern
            # 使用一批随机干净输入
            x_clean = torch.rand(16, *input_shape, device=device)
            m = torch.sigmoid(mask)
            x_triggered = (1 - m) * x_clean + m * torch.sigmoid(pattern)

            output = model(x_triggered)
            # 最大化目标类别的概率
            class_loss = nn.CrossEntropyLoss()(output, torch.full((16,), target_class, device=device))
            # 最小化触发器大小（掩码的 L1 范数）
            reg_loss = torch.sigmoid(mask).sum()

            loss = class_loss + 0.01 * reg_loss
            loss.backward()
            optimizer.step()

        final_mask = torch.sigmoid(mask).detach()
        trigger_size = final_mask.sum().item()
        results[target_class] = {
            "trigger_size": trigger_size,
            "mask": final_mask,
            "pattern": torch.sigmoid(pattern).detach(),
        }
        print(f"类别 {target_class}: 触发器 L1 范数 = {trigger_size:.2f}")

    # 检测异常: 后门类别的触发器显著更小
    sizes = [r["trigger_size"] for r in results.values()]
    median_size = np.median(sizes)
    mad = np.median([abs(s - median_size) for s in sizes])

    for cls, r in results.items():
        anomaly_score = abs(r["trigger_size"] - median_size) / (mad + 1e-10)
        if anomaly_score > 2.0 and r["trigger_size"] < median_size:
            print(f"\n*** 检测到后门: 类别 {cls} (异常分数: {anomaly_score:.2f})")
            print(f"    触发器大小: {r['trigger_size']:.2f} vs 中位数: {median_size:.2f}")
            return cls, r

    print("\n未检测到后门。")
    return None, None

# 替代方法: 激活聚类
def activation_clustering(model, data_loader, layer_name, num_classes):
    """
    通过聚类倒数第二层的激活值来检测后门。
    投毒样本在激活空间中会形成一个独立的聚类。
    """
    from sklearn.cluster import KMeans
    from sklearn.decomposition import PCA

    activations = {c: [] for c in range(num_classes)}
    hooks = []

    def get_activation(name):
        def hook(model, input, output):
            activations["current"] = output.detach().cpu().numpy()
        return hook

    # 在倒数第二层注册 hook
    for name, module in model.named_modules():
        if name == layer_name:
            hooks.append(module.register_forward_hook(get_activation(name)))

    # 收集激活值
    model.eval()
    class_activations = {c: [] for c in range(num_classes)}
    with torch.no_grad():
        for x, y in data_loader:
            model(x)
            act = activations["current"].reshape(x.shape[0], -1)
            for i, label in enumerate(y):
                class_activations[label.item()].append(act[i])

    for h in hooks:
        h.remove()

    # 对每个类别，聚类激活值并检查是否存在分离
    for cls in range(num_classes):
        acts = np.array(class_activations[cls])
        if len(acts) < 10:
            continue

        # 降维并聚类
        pca = PCA(n_components=10)
        reduced = pca.fit_transform(acts)
        kmeans = KMeans(n_clusters=2, random_state=0).fit(reduced)

        # 如果一个聚类远小于另一个，可能是投毒子集
        counts = np.bincount(kmeans.labels_)
        ratio = min(counts) / max(counts)
        if ratio < 0.35:  # 35% 阈值
            print(f"类别 {cls}: 可疑聚类分裂 ({counts[0]} vs {counts[1]})")

# 用法
backdoor_class, trigger_info = neural_cleanse(
    model, num_classes=10, input_shape=(3, 32, 32)
)
```

**核心洞察：** Neural Cleanse 找到能导致所有输入被误分类到每个类别的最小扰动。后门类别需要异常小的触发器（即后门模式）。激活聚类检测投毒样本在倒数第二层的激活空间中是否与干净样本分开聚类。在 CTF 挑战中，这些技术帮助你识别哪个类别被植入了后门并重建触发模式。

---

## foolbox L1BasicIterativeAttack 攻击 Keras MNIST-Auth (nullcon 2019)

**模式：** 一个 Keras 模型对 28x28 灰度"头像"（以 URL 中的十六进制 blob 序列化）进行分类，仅当预测类别匹配目标时才授予访问权限。foolbox 包装 Keras 模型并运行 L1 有界迭代攻击，找到稀疏的、低幅度扰动——非常适合小图像和可完全控制输入比特流的 CTF 解题者。

```python
# pip install foolbox==2.4.0 keras==2.3.1 tensorflow==1.15
import numpy as np
import foolbox
from keras.models import load_model

model = load_model('auth.h5')                              # 10 类 MNIST 风格
fmodel = foolbox.models.KerasModel(model,
                                   bounds=(0, 255),
                                   preprocessing=(0, 255))  # 除以 255

attack = foolbox.attacks.L1BasicIterativeAttack(fmodel)

target_class = 0
start = (np.random.rand(28, 28, 1) * 255).astype('float32')
adv = attack(start, target_class)                           # 返回对抗图像
assert np.argmax(model.predict(adv[None, ...])) == target_class

# 以挑战要求的十六进制字符串格式序列化
profile = ''.join('0x%02x' % int(v) for v in adv.ravel())
```

**核心洞察：** foolbox 是从"已有 Keras 模型 + 目标类别"到可用对抗样本的最短路径。`L1BasicIterativeAttack` 产生稀疏扰动，仅改变少量像素——非常适合小灰度输入（MNIST/Fashion-MNIST 规模），因为 L-inf 攻击会触及每个像素，无法通过"大致看起来像数字 N"的完整性检查。请固定 `foolbox==2.x`，因为 v3 API 不兼容。

**参考资料：** nullcon HackIM 2019 — ML-Auth, writeup 13058

---

## 手写 Keras FGSM（通过 K.gradients）(UTCTF 2019)

**模式：** 人脸验证类挑战，目标模型为 Keras/TF1，输入为 RGB 整数数组（0..255），挑战要求*目标*误分类。当 foolbox 的预处理假设不适用（整数像素、自定义损失）时，使用 `keras.backend.gradients()` 手写 FGSM 来获取任务特定损失关于输入的梯度，然后以 `eps=1`（对整数像素安全）迭代地沿梯度符号方向步进。

```python
import keras, numpy as np
from keras.models import load_model
from keras import backend as K
from PIL import Image

TARGET = 4
eps = 1                       # 整数步长确保像素保持在 uint8 范围内

model = load_model('model.model')
img = np.asarray(Image.open('img2.png'), dtype='int32')

# 独热目标和 MSE(target, output) 关于输入的符号梯度
t = np.zeros(model.output_shape[-1]); t[TARGET] = 1
grad_op = K.gradients(keras.losses.mean_squared_error(t, model.output),
                      model.input)
sess = K.get_session()

x = img.copy()
while np.argmax(model.predict(x[None, ...])) != TARGET:
    g = sess.run(grad_op, feed_dict={model.input: x[None, ...]})[0][0]
    x = x - np.sign(g * eps)            # 下降以最小化到目标的损失
    x = np.clip(x, 0, 255)              # 保持有效 RGB 范围

Image.fromarray(x.astype('uint8'), 'RGB').save('adv.png')
```

**核心洞察：** `K.gradients(loss, model.input)` 暴露了完整的符号输入梯度，因此你可以用 Keras 运算表达任何损失作为攻击面——目标 MSE、到特定类别的交叉熵，甚至是与另一幅图像倒数第二层激活的特征匹配。`eps=1` 配合裁剪保证了 uint8 兼容的对抗样本（不会出现保存为 PNG 时静默量化导致扰动消失的问题），这在服务器重新读取 PNG 时非常重要。

**参考资料：** UTCTF 2019 — FaceSafe, writeup 13801
