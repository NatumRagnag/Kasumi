# HymoFS

HymoFS 是一个面向 Android GKI/Linux 的外置内核模块（LKM，产物为 `hymofs_lkm.ko`），用于 root/SU 场景下的路径控制。

它通过“匿名 fd + `ioctl`”控制面提供重定向、隐藏、合并/注入与伪装能力。

English version： [README.md](./README.md)

## 当前状态

- 仓库形态：LKM（不是 in-tree 内核补丁）
- 主代码目录：`src/`
- 协议定义：`src/include/hymofs_uapi.h`
- 当前协议版本：`HYMO_PROTOCOL_VERSION = 15`
- Hook 策略：优先 ftrace/tracepoint，不可用时回退 kprobe/kretprobe
- 已包含 `arch_ftrace_get_regs` 在 6.6+ 的兼容处理

## 主要能力

- 路径重定向：`src -> target`
- 路径展示反向映射（`d_path` 相关）
- 目录隐藏（`iterate_dir` 过滤）
- 目录合并/注入
- `kstat` 伪装（ino/dev/size/time 等）
- overlay/xattr 相关过滤
- `uname` 伪装
- `/proc/cmdline` 伪装
- `/proc/<pid>/maps` 规则伪装（ino/dev/pathname）
- mount hide、statfs spoof

> 该模块会拦截 VFS 与 syscall 热路径，请仅在可控环境使用。

## Hook 架构

- GET_FD：`tracepoint` 优先，失败回退 `kprobe/kretprobe`
- VFS：`ftrace(entry) + kretprobe(ret)` 优先，失败回退 `kprobe`
- 符号解析：优先 `kallsyms_lookup_name`，失败回退逐符号 kprobe 解析

## CI 覆盖 KMI

- `android12-5.10`
- `android13-5.10`
- `android13-5.15`
- `android14-5.15`
- `android14-6.1`
- `android15-6.6`
- `android16-6.12`

对应工作流：`.github/workflows/build-lkm.yml`、`.github/workflows/ddk-lkm.yml`。

## 构建

### 方式 A：DDK（推荐）

```bash
ddk build
ddk build android14-6.1
ddk build android15-6.6
```

### 方式 B：内核源码树本地构建

先完成目标内核 `modules_prepare`，再执行：

```bash
make -C /path/to/kernel ARCH=arm64 M=$(pwd)/src modules
```

## 加载与调试参数

```sh
insmod hymofs_lkm.ko
```

如遇符号不全无法加载，且使用新版 KernelSU 及其分支,可尝试

```sh
ksud insmod hymofs_lkm.ko
```

常用参数（定义于 `src/core/hymofs_bootstrap.c`）：

- `hymo_syscall_nr`
- `hymo_no_tracepoint=1`
- `hymo_skip_vfs=1`
- `hymo_skip_extra_kprobes=1`
- `hymo_skip_getfd=1`
- `hymo_skip_kallsyms=1`
- `hymo_dummy_mode=1`

## 用户态控制面

1. 用户态通过 GET_FD 获取匿名 fd（仅 root）。
2. 对该 fd 发送 `ioctl` 管理规则与特性。

常用 ioctl（完整 ABI 见 `src/include/hymofs_uapi.h`）：

- `HYMO_IOC_ADD_RULE`、`HYMO_IOC_DEL_RULE`、`HYMO_IOC_HIDE_RULE`
- `HYMO_IOC_ADD_MERGE_RULE`、`HYMO_IOC_CLEAR_ALL`、`HYMO_IOC_SET_ENABLED`
- `HYMO_IOC_GET_FEATURES`、`HYMO_IOC_GET_HOOKS`、`HYMO_IOC_LIST_RULES`
- `HYMO_IOC_ADD_SPOOF_KSTAT`、`HYMO_IOC_UPDATE_SPOOF_KSTAT`
- `HYMO_IOC_SET_UNAME`、`HYMO_IOC_SET_CMDLINE`
- `HYMO_IOC_ADD_MAPS_RULE`、`HYMO_IOC_CLEAR_MAPS_RULES`
- `HYMO_IOC_SET_MOUNT_HIDE`、`HYMO_IOC_SET_MAPS_SPOOF`、`HYMO_IOC_SET_STATFS_SPOOF`

建议直接复用 [hymo](https://github.com/Anatdx/hymo) 用户态实现（C++），避免结构体或 ABI 版本不一致；  
另有 Anatdx 本人维护的 [YukiSU](https://github.com/Anatdx/YukiSU) 提供与 KernelSU 集成的实现（C++），  
以及 Anatdx 参与开发的 [hybrid-mount](https://github.com/Hybrid-Mount/meta-hybrid_mount) 元模块也加入了 HymoFS 支持与用户态实现（Rust）。

> 由于 hymo 模块挂载逻辑并不优秀且更新频率缓慢，我推荐使用更优秀的 hybrid-mount 作为元模块使用

## 快速排障

- 出现 `Unknown symbol __tracepoint_sys_enter`：尝试 `hymo_no_tracepoint=1`
- 可编译但无法加载：检查 `vermagic`、模块签名策略和 `dmesg`
- 调整 hook/ABI 后：优先用 `HYMO_IOC_GET_HOOKS` 与 `HYMO_IOC_GET_FEATURES` 做运行态自检

## 许可证

- SPDX：`Apache-2.0 OR GPL-2.0`
- 详见：`LICENSE`、`LICENSE-GPL-2.0`、`NOTICE`
