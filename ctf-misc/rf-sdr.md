# CTF Misc - RF / SDR / IQ 信号处理

使用同相/正交（IQ）数据进行软件定义无线电（SDR）信号处理的技术。

## IQ 文件格式
- **cf32**（复数浮点32）：GNU Radio 标准，`np.fromfile(path, dtype=np.complex64)`
- **cs16**（复数有符号16位）：`np.fromfile(path, dtype=np.int16).reshape(-1,2)`，然后 `I + jQ`
- **cu8**（复数无符号8位）：RTL-SDR 原始格式

## 分析流程
```python
import numpy as np
from scipy import signal

# 1. 载入 IQ 数据
iq = np.fromfile('signal.cf32', dtype=np.complex64)

# 2. 频谱分析 - 查找占用频段
fft_data = np.fft.fftshift(np.fft.fft(iq[:4096]))
freqs = np.fft.fftshift(np.fft.fftfreq(4096))
power_db = 20*np.log10(np.abs(fft_data)+1e-10)

# 3. 通过循环平稳分析识别符号率
x2 = np.abs(iq_filtered)**2  # 幅度平方
fft_x2 = np.abs(np.fft.fft(x2, n=65536))
# fft_x2 的峰值 = 符号率 (samples_per_symbol = 1/peak_freq)

# 4. 频率偏移到基带
center_freq = 0.14  # 频段中心的归一化频率
t = np.arange(len(iq))
baseband = iq * np.exp(-2j * np.pi * center_freq * t)

# 5. 低通滤波以隔离频段
lpf = signal.firwin(101, bandwidth/2, fs=1.0)
filtered = signal.lfilter(lpf, 1.0, baseband)
```

## 带载波和定时恢复的 QAM-16 解调
QAM-16（正交振幅调制）——关键挑战是载波频偏导致星座图旋转（点变成圆圈）。

**判决导向载波恢复 + Mueller-Muller 定时恢复：**
```python
# 环路参数（二阶 PLL）
carrier_bw = 0.02  # 较宽带宽 = 更快跟踪，但噪声更多
damping = 1.0
theta_n = carrier_bw / (damping + 1/(4*damping))
Kp = 2 * damping * theta_n      # 比例增益
Ki = theta_n ** 2                # 积分增益

carrier_phase = 0.0
carrier_freq = 0.0

for each symbol sample:
    # 用当前相位估计去旋转
    symbol = raw_sample * np.exp(-1j * carrier_phase)

    # 找到最近的星座点（判决）
    nearest = min(constellation, key=lambda p: abs(symbol - p))

    # 相位误差（判决导向）
    error = np.imag(symbol * np.conj(nearest)) / (abs(nearest)**2 + 0.1)

    # 更新二阶环路
    carrier_freq += Ki * error
    carrier_phase += Kp * error + carrier_freq
```

**Mueller-Muller 定时误差检测器：**
```python
timing_error = (Re(y[n]-y[n-1]) * Re(d[n-1]) - Re(d[n]-d[n-1]) * Re(y[n-1]))
             + (Im(y[n]-y[n-1]) * Im(d[n-1]) - Im(d[n]-d[n-1]) * Im(y[n-1]))
# y = 接收符号，d = 判决（最近星座点）
```

## RF CTF 挑战的关键洞见
- **星座图中的圆圈** = 恒定频偏（点以固定速率旋转，形成环）
- **螺旋形** = 频偏随时间漂移（环半径随幅度/AGC漂移变化）。如果看到点沿外扩弧线而非闭合圆圈，怀疑频率和增益不稳定同时存在
- **网格上的斑点** = 同步正确，仅为噪声
- **4 倍歧义**：判决导向载波恢复可能锁定在 0/90/180/270 度旋转 - 尝试所有 4 种情况
- **带宽与符号率**：BW = Rs × (1 + alpha)，其中 alpha 是滚降因子（0 到 1）
- **RC 与 RRC**：“RC 脉冲成形”在发射端意味着接收端只需采样（无需匹配滤波）；“RRC”意味着接收端需应用匹配的 RRC 滤波器
- **循环平稳峰值在 Rs 处** 即使不知道调制阶数也能确认符号率
- **AGC**：归一化信号功率以匹配星座功率：`scale = sqrt(target_power / measured_power)`
- **GNU Radio 的 QAM-16 默认映射** 不是 Gray 码 - 始终检查提供的星座映射图
## 常见帧结构模式
- 链路空闲时重复的空闲/同步模式
- 起始定界符（通常是单个符号，如 0）
- 数据负载（QAM-16 的半字节对：高半字节优先，低半字节）
- 结束定界符（与起始定界符相同，例如 0）
- 空闲模式本身可能包含定界符值——通过上下文区分（它是否属于16符号的重复模式？）
