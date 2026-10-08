# wechatauto Linux 支持指南

> 状态：**读库路线已自测通过；UI 后端与 headless 链路需真机验证**（本仓库的开发
> 环境是无 GUI 的容器，装不了可交互的微信）。Windows 版接口一字未动。

## 一、各路线在 Linux 上的状态

| 能力 | Linux 状态 | 说明 |
|---|---|---|
| 读消息 / 会话 / 联系人 / 朋友圈读 | ✅ 可用 | `wechatauto.db.WeChatDB`，同一套代码 |
| 数据库密钥提取 | ✅ 可用 | `wechatauto.linux_key`，一次性 root 扫描 |
| 媒体 AES 解密（图片 .dat） | ✅ 可用 | 纯密码学运算 |
| 图片密钥派生（cfgDword） | ⚠️ 无 | 依赖 Windows weixin.dll cfg 指针链 |
| 发消息 / 界面操作 | 🟡 待校准 | `wechatauto.linux_ui`（AT-SPI2），选择器需真机 probe |
| sway headless 扫码登录 | 🟡 待真机 | `tools/sway-headless/`，脚本逻辑已在沙箱内跑通 |

## 二、安装

```bash
pip install -e .            # Linux 基础安装（纯读库，零 Windows 依赖）
pip install -e .[windows]   # Windows 全功能（Linux 上装不了也不需要）
```

UI 后端的系统依赖（pip 装不了）：

```bash
# Debian/Ubuntu
sudo apt install python3-gi gir1.2-atspi-2.0 at-spi2-core \
                 sway grim wl-clipboard wtype
# Arch
sudo pacman -S python-gobject at-spi2-core sway grim wl-clipboard wtype
```

## 三、读取消息（已自测）

密钥是**账号绑定的静态值**：微信重启不换钥、更新不重加密（原项目正是靠这点把
keys.json 跨会话复用，并且每次加载都用页 1 HMAC 重新验证、失效自动重取）。
因此 root 只需要成功用一次，之后普通用户读库零特权——**不需要常驻 root 守护
进程**（常驻反而扩大权限面）。

```bash
# 1) 登录微信 Linux 客户端（官方版 / flatpak com.tencent.WeChat）
# 2) 一次性 root 取钥（自动探测 ~/xwechat_files，多账号全支持）
sudo python -m wechatauto.linux_key
#    可选: --db-dir ~/xwechat_files  --deep（锚点未命中时堆区深扫）
#    可选: --watch N（每 N 秒重扫；密钥静态，正常无需开启）
# 3) 普通用户直接读
python -c "from wechatauto import WeChatDB; \
           print(WeChatDB().list_recent_messages('文件传输助手', limit=5))"
```

密钥缓存两处（0600，原子写）：`/tmp/wechatauto_db/<账号>/keys.json` 与
`~/.local/share/wechatauto_keys/<账号>.json`（可用 `WECHATAUTO_KEYS_DIR` 覆盖）。

**如果哪天缓存校验失败**（重装账号、版本改加密方案）：`WeChatDB` 会明确报
「0/N 个密钥可用」，此时重跑一次第 2 步即可。真正的动态密钥场景请用
`--watch` 模式跑在 systemd 里（`Type=simple, User=root`，它只读内存、只写
keys.json 两处文件，权限面已最小化）。

### Linux 提取原理（与 Windows 版差异）

| | Windows | Linux |
|---|---|---|
| 读内存 | `OpenProcess` + `ReadProcessMemory` | `/proc/<pid>/mem` + `/proc/<pid>/maps` |
| 定位密钥 | Config.Cipher 对象指针链 + DLL movabs XOR 材料 | 字符串锚点附近 ±128KB 滑窗（快）→ 堆区全量滑窗兜底（`--deep`） |
| 校验 | SQLCipher 4 页 1 HMAC（同一套 `_verify_enc_key`，零误报） | 同左 |

## 四、界面自动化（`wechatauto.linux_ui`）

对应关系：UIA → AT-SPI2；win32 剪贴板/键盘 → wl-clipboard + wtype（Wayland）
或 xclip + xdotool（X11）；`WeChatDB` 编排逻辑原样复用。

```python
from wechatauto.linux_ui import WeChatLinux
wx = WeChatLinux(db_dir="~/xwechat_files")   # db 属性即 WeChatDB
wx.SendMsg("你好", who="文件传输助手")        # 打开会话 → 粘贴 → 回读校验 → 回车
```

**必须先校准**：微信控件在无障碍树里的名称需要真机确认。在登录了微信的桌面
会话里跑：

```bash
QT_ACCESSIBILITY=1 python -m wechatauto.linux_ui.probe -o tree.json
```

按树里的实际名称写 `~/.config/wechatauto_linux/calibration.json`：

```json
{"search_box_keys": ["搜索"], "input_box_keys": ["输入"], "send_button_keys": ["发送"]}
```

已内置与 Windows 版同款的防呆：发送前回读输入框比对（比率 0.6，表情码折叠
口径同 v1.2.5），不达标清空输入框、不发送、抛错。

## 五、sway headless 扫码登录（`tools/sway-headless/`）

无显示器的服务器/CI 上完整复现「启动微信 → 扫码 → 进入可自动化状态」：

```bash
./tools/sway-headless/launch-wechat.sh
# 产物（SESSION_DIR，默认 ./wechat-headless-session/）:
#   qr.png       登录二维码，每 2s 刷新，直接用手机扫
#   login.state  登录成功后写入
#   env          后续自动化 source 的环境变量（SWAYSOCK/WAYLAND_DISPLAY）
```

扫码成功后接着跑 `sudo python -m wechatauto.linux_key`（root 一次性）即可开始
读库。脚本要点：

- `WLR_BACKENDS=headless WLR_RENDERER=pixman`：无 GPU 软渲染；
- `QT_LINUX_ACCESSIBILITY_ALWAYS=1`：让 AT-SPI2 能读到微信 Qt 控件树（UI 后端
  的前提）；
- 二维码窗口用 `swaymsg get_tree` 定位 + `grim` 精确裁剪（无 jq 时整屏兜底）；
- 登录检测：登录窗消失 + 主窗出现（`QR_TITLE_RE` / `MAIN_TITLE_RE` 可覆盖）。

## 六、已在沙箱验证 / 未验证清单

**已验证**（无微信、无 GUI 的容器里完成）：
- Linux 上 `pip install -e .` 成功；`import wechatauto` / CLI 全部可运行；
- `tools/test_linux_key.py` 三项自测全过：伪 SQLCipher 库（真 HMAC 格式）+
  种子进程内存 → 扫描命中且校验通过；错钥必拒；`WeChatDB` 纯缓存解库 2/2；
- sway headless 会话真实启动成功（IPC socket / `get_tree` / 输出查询正常），
  启动脚本语法与依赖探测、env 文件产出验证通过。

**待真机验证**：
- 对真实微信 Linux 客户端的锚点扫描命中率（锚点失败会自动落 `--deep`，
  代价是分钟级扫描）；
- AT-SPI2 后端的选择器与发送链路（`probe` 工具已备好校准路径）；
- headless 微信扫码登录全链路（沙箱里的 /opt/wechat 因容器缺 GUI 设备
  无法长活，非脚本问题）。

Windows 用户完全不受影响：所有 Windows 代码路径保持原样。
