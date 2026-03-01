# KoKo SSH 国密算法支持

> **状态**: 已实现
> **分支**: dev_perf_gm
> **更新日期**: 2026-03-01

## 1. 背景与目标

KoKo 通过 2222 端口暴露 SSH 服务，基于 `golang.org/x/crypto/ssh`。
目标：在 SSH 协议层集成国密算法（SM2/SM3/SM4），实现混合模式（国密 + 国际标准并存），满足安全合规要求。

## 2. 架构

```
┌─────────────────────────────────────────────────┐
│                KoKo 应用层                        │
│  pkg/sshd/server.go   → 配置 GM 算法列表          │
│  pkg/sshd/hostkey.go  → SM2 密钥持久化与加载       │
│  pkg/srvconn/ssh.go   → 客户端 GM 算法支持         │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│       本地 fork: crypto/ssh (基于 x/crypto)       │
│  ssh/cipher.go   → SM4-CTR, SM4-GCM             │
│  ssh/mac.go      → HMAC-SM3, HMAC-SM3-96        │
│  ssh/kex.go      → 注册 SM2 密钥交换              │
│  ssh/kex_sm2.go  → SM2KAP 密钥交换实现            │
│  ssh/keys.go     → SM2 密钥类型注册               │
│  ssh/keys_sm2.go → SM2 公钥/签名/解析             │
│  ssh/common.go   → 所有 GM 算法名称常量            │
│  ssh/transport.go→ HashFunc 支持 SM3 密钥派生      │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│        emmansun/gmsm v0.41.0 (纯 Go)            │
│  sm2 → 椭圆曲线 (密钥交换 + 签名 + CalculateZA)   │
│  sm3 → 杂凑算法 (MAC + KDF), hash.Hash 接口      │
│  sm4 → 分组密码 (对称加密), cipher.Block 接口      │
│  特性: AVX2/NEON 硬件加速, 无 CGO 依赖            │
└─────────────────────────────────────────────────┘
```

## 3. 已实现算法

### 3.1 对称加密（SM4）

| SSH 算法名 | 模式 | 密钥长度 | IV 长度 | 实现文件 |
|-----------|------|---------|--------|---------|
| `sm4-ctr` | CTR | 16B | 16B | `ssh/cipher.go` |
| `sm4-gcm` | GCM/AEAD | 16B | 12B | `ssh/cipher.go` |

### 3.2 MAC（SM3）

| SSH 算法名 | 输出长度 | 密钥长度 | 实现文件 |
|-----------|---------|---------|---------|
| `hmac-sm3` | 32B (256bit) | 32B | `ssh/mac.go` |
| `hmac-sm3-96` | 12B (96bit) | 32B | `ssh/mac.go` |

### 3.3 密钥交换（SM2KAP）

| SSH 算法名 | 曲线 | 哈希 | 实现文件 |
|-----------|------|------|---------|
| `ecdh-sm2p256v1-sm3` | SM2P256V1 | SM3 | `ssh/kex_sm2.go` |
| `sm2-sm3` | SM2P256V1 | SM3 | `ssh/kex_sm2.go` |

**密钥交换协议**: 使用 SM2 密钥协商协议（SM2KAP，GM/T 0003-2012），非标准 ECDH。
详见下方 [SM2KAP 实现说明](#4-sm2kap-实现说明)。

### 3.4 主机密钥（SM2 签名）

| SSH 算法名 | 签名方式 | 实现文件 |
|-----------|---------|---------|
| `sm2` | SM2 + SM3 (DefaultSM2SignerOpts) | `ssh/keys_sm2.go` |

SM2 主机密钥持久化于 `data/keys/.sm2_host_key`，首次启动自动生成，后续重启复用。

## 4. SM2KAP 实现说明

密钥交换使用 SM2 密钥协商协议（SM2KAP），与 openEuler OpenSSH (`OpenSSH_9.1`) 兼容。

### 协议细节

在 SSH 场景下，静态密钥 = 临时密钥（即 `dA = rA`, `PA = RA`）：

1. **计算 w**: `w = (N.BitLen() + 1) / 2 - 1` = 127（SM2 曲线）
2. **AVF 函数**: `avf(x) = 2^w + (x & (2^w - 1))`
3. **计算 t**: `t = (d + avf(localPub.X) * d) mod N`
4. **计算基点**: `base = peerPub + [avf(peerPub.X)] * peerPub`
5. **计算共享点**: `V = [t] * base`
6. **计算 Z 值**: `ZA = sm2.CalculateZA(clientPub, uid)`, `ZB = sm2.CalculateZA(serverPub, uid)`
7. **KDF 派生**: `sharedKey = sm3.Kdf(V.X || V.Y || ZA || ZB, keyLen)`

### 关键兼容性细节

- **UID**: 必须使用原始字节 `{0x01, 0x02, ..., 0x08, 0x01, 0x02, ..., 0x08}`，
  **不是** SM2 标准默认的 ASCII `"1234567812345678"`（`{0x31, 0x32, ...}`）。
  这与 openEuler OpenSSH 的 `kexsm2.c` 中 `unsigned char id[16] = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8}` 保持一致。
- **Z 值顺序**: 始终为 `ZA(client) || ZB(server)`，无论本端是客户端还是服务端。
- **HashFunc**: SM3 无 `crypto.Hash` 常量，通过 `kexResult.HashFunc` 字段传递 `sm3.New`，
  在 `transport.go` 的 `generateKeyMaterial` 中优先使用。

## 5. 文件变更清单

### crypto/ssh（本地 fork）

| 文件 | 变更 |
|------|------|
| `ssh/cipher.go` | +SM4-CTR (`newSM4CTR`), +SM4-GCM (`newSM4GCMCipher`) |
| `ssh/mac.go` | +HMAC-SM3, +HMAC-SM3-96 |
| `ssh/common.go` | +算法名称常量, 注册到 supported 列表 |
| `ssh/kex.go` | +`kexResult.HashFunc` 字段, 注册 SM2 kex 到 `kexAlgoMap` |
| `ssh/kex_sm2.go` | **新增** SM2KAP 密钥交换实现 (`sm2ECDH`, `sm2KAPComputeKey`) |
| `ssh/keys.go` | +SM2 密钥类型识别 (`KeyAlgoSM2`), `NewSignerFromKey` 支持 SM2 |
| `ssh/keys_sm2.go` | **新增** SM2 公钥/签名/解析 (`sm2PublicKey`, `sm2Signer`, `parseSM2`) |
| `ssh/transport.go` | `generateKeyMaterial` 优先使用 `HashFunc`（支持 SM3） |

### KoKo 应用层

| 文件 | 变更 |
|------|------|
| `go.mod` | +`emmansun/gmsm v0.41.0` 依赖 |
| `pkg/sshd/server.go` | 配置 `supportedMACs`, `supportedKexAlgos`, `supportedCiphers` 包含国密算法 |
| `pkg/sshd/hostkey.go` | SM2 主机密钥生成 + 持久化到 `data/keys/.sm2_host_key` |
| `pkg/srvconn/ssh.go` | 客户端侧追加 SM4 cipher 和 SM2 kex |

## 6. 测试验证

### 编译

```bash
cd crypto && go build ./ssh/...
cd .. && go build ./...
```

### 国密连接测试（openEuler OpenSSH 客户端）

```bash
ssh -o HostKeyAlgorithms=sm2 \
    -o Ciphers=sm4-ctr \
    -o MACs=hmac-sm3 \
    -o KexAlgorithms=sm2-sm3 \
    -vvv admin@<jumpserver-ip> -p2222
```

### 标准连接兼容性

```bash
# 普通 OpenSSH 客户端仍可正常连接（混合模式）
ssh -p 2222 user@<jumpserver-ip>
```

## 7. 注意事项

| 项目 | 说明 |
|------|------|
| 本地 fork 维护 | `crypto/ssh` 为项目内 fork，上游更新需手动同步 |
| 混合模式 | 国密算法与国际标准算法并存，客户端按优先级协商 |
| SM2 曲线 | SM2P256V1 与 NIST P-256 是不同曲线，密钥不可互换 |
| 客户端要求 | 国密连接需支持 SM2/SM3/SM4 的 SSH 客户端（如 openEuler OpenSSH） |
| gmsm 版本 | 锁定 `emmansun/gmsm v0.41.0`，纯 Go + 汇编优化，无 CGO 依赖 |

## 8. 参考资料

- [GM/T 0003-2012](http://www.gmbz.org/) — SM2 密钥协商协议
- [emmansun/gmsm](https://github.com/emmansun/gmsm) — Go 国密库
- [openEuler OpenSSH SM 补丁](https://gitee.com/src-openeuler/openssh) — `feature-add-SMx-support.patch`
- [RFC 4253](https://tools.ietf.org/html/rfc4253) — SSH Transport Layer Protocol
