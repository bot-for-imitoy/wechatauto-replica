#!/usr/bin/env bash
# ============================================================================
# sway headless 启动微信 Linux 客户端 → 二维码落盘 → 等待扫码登录 → 自动化就绪
#
# 用法:
#   ./launch-wechat.sh                # 前台守护；登录成功后打印提示并保持会话
#   SESSION_DIR=/tmp/wxsession ./launch-wechat.sh
#   WECHAT_CMD="/opt/wechat/wechat" ./launch-wechat.sh
#
# 产物（默认在 $PWD/wechat-headless-session/）:
#   qr.png          登录二维码（每 2 秒刷新，直接用手机微信扫它）
#   login.state     登录成功后写入（内容为时间戳）
#   env             后续自动化要 source 的环境变量（SWAYSOCK/WAYLAND_DISPLAY）
#
# 依赖: sway(>=1.7, 无头模式)、grim；可选 jq（二维码窗口精确裁剪）。
# 微信命令自动探测顺序: $WECHAT_CMD > flatpak com.tencent.WeChat >
# /opt/wechat/wechat > PATH 里的 wechat。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_DIR="${SESSION_DIR:-$PWD/wechat-headless-session}"
QR_FILE="$SESSION_DIR/qr.png"
QR_TMP="$SESSION_DIR/.qr.tmp.png"
LOGIN_STATE="$SESSION_DIR/login.state"
ENV_FILE="$SESSION_DIR/env"
SWAY_CONFIG="$SCRIPT_DIR/sway-config"

# 登录窗口 / 主窗口标题的识别正则（真机不同版本可自行覆盖）
QR_TITLE_RE="${QR_TITLE_RE:-登录|扫码|login|scan}"
MAIN_TITLE_RE="${MAIN_TITLE_RE:-微信|WeChat|wechat}"
POLL_INTERVAL="${POLL_INTERVAL:-2}"
LOGOUT_TIMEOUT="${LOGOUT_TIMEOUT:-300}"   # 二维码最长等待秒数

die() { echo "[launch] $*" >&2; exit 1; }
log() { echo "[launch] $*" >&2; }

# ---- 依赖检查 ---------------------------------------------------------------
command -v sway >/dev/null || die "缺少 sway（无头合成器）。Debian/Ubuntu: apt install sway"
command -v grim >/dev/null || die "缺少 grim（截图）。Debian/Ubuntu: apt install grim"
HAVE_JQ=0; command -v jq >/dev/null && HAVE_JQ=1

# ---- 微信命令探测 -----------------------------------------------------------
if [[ -z "${WECHAT_CMD:-}" ]]; then
    if command -v flatpak >/dev/null && flatpak info com.tencent.WeChat >/dev/null 2>&1; then
        WECHAT_CMD="flatpak run com.tencent.WeChat"
    elif [[ -x /opt/wechat/wechat ]]; then
        WECHAT_CMD="/opt/wechat/wechat"
    elif command -v wechat >/dev/null; then
        WECHAT_CMD="wechat"
    else
        die "找不到微信 Linux 客户端。请用 WECHAT_CMD=... 指定启动命令。"
    fi
fi
log "微信命令: $WECHAT_CMD"

# ---- 会话目录 ---------------------------------------------------------------
mkdir -p "$SESSION_DIR"
rm -f "$QR_FILE" "$QR_TMP" "$LOGIN_STATE"
: > "$ENV_FILE"

# ---- 启动 headless sway -----------------------------------------------------
export WLR_BACKENDS=headless
export WLR_LIBINPUT_NO_DEVICES=1
export WLR_RENDERER=pixman                     # 无 GPU 也能软渲染
export QT_QPA_PLATFORM=wayland                 # 微信 Qt 客户端走 wayland
export QT_LINUX_ACCESSIBILITY_ALWAYS=1         # 关键：让 AT-SPI2 能读到 Qt 控件树
export QT_ACCESSIBILITY=1
export GTK_MODULES="${GTK_MODULES:-gail:atk-bridge}"

SWAY_PID=""
cleanup() {
    [[ -n "${HEALTH_PID:-}" ]] && kill "$HEALTH_PID" 2>/dev/null || true
    [[ -n "${WECHAT_PID:-}" ]] && kill "$WECHAT_PID" 2>/dev/null || true
    [[ -n "$SWAY_PID" ]] && kill "$SWAY_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export XDG_RUNTIME_DIR
mkdir -p "$XDG_RUNTIME_DIR"

sway -c "$SWAY_CONFIG" &
SWAY_PID=$!

# 找 sway 的 IPC socket 与 wayland socket（wlroots 会新建 wayland-N）
for _ in $(seq 1 50); do
    SWAYSOCK="$(ls -t "$XDG_RUNTIME_DIR"/sway-ipc.*.sock 2>/dev/null | head -1 || true)"
    [[ -n "$SWAYSOCK" ]] && break
    sleep 0.2
done
[[ -n "${SWAYSOCK:-}" ]] || die "sway IPC socket 未出现，启动失败"
WAYLAND_DISPLAY="$(ls -t "$XDG_RUNTIME_DIR" 2>/dev/null | grep '^wayland-' | head -1 || true)"
export SWAYSOCK WAYLAND_DISPLAY

cat > "$ENV_FILE" <<EOF
export SWAYSOCK='$SWAYSOCK'
export WAYLAND_DISPLAY='${WAYLAND_DISPLAY:-}'
export QT_QPA_PLATFORM=wayland
export QT_LINUX_ACCESSIBILITY_ALWAYS=1
EOF
log "sway headless 已就绪 (SWAYSOCK=$SWAYSOCK)"

smsg() { swaymsg -s "$SWAYSOCK" "$@"; }

# ---- 拉起微信 ---------------------------------------------------------------
$WECHAT_CMD &
WECHAT_PID=$!
log "微信已拉起（pid=$WECHAT_PID），等待登录窗口出现…"

# 微信若秒退，早失败早暴露（容器/缺 GPU 库/缺 XWayland 都会导致静默退出）
(
    wait $WECHAT_PID 2>/dev/null
    rc=$?
    if ! kill -0 "$WECHAT_PID" 2>/dev/null && [[ ! -f "$LOGIN_STATE" ]]; then
        sleep 3
        if [[ ! -f "$LOGIN_STATE" ]] && ! kill -0 "$WECHAT_PID" 2>/dev/null; then
            log "警告: 微信进程已退出（rc=$rc）。常见原因: 容器缺 GUI 设备、"
            log "缺少 libGBM/VAAPI、微信需要 XWayland。可用 \$WECHAT_CMD 换用手动命令重试。"
        fi
    fi
) &
HEALTH_PID=$!

# ---- 工具函数 ---------------------------------------------------------------
# 从 get_tree 里找标题匹配 $1 的窗口，输出 "OUTNAME x y W H"（无 jq 返回空）
find_window() {
    local re="$1"
    if [[ "$HAVE_JQ" != 1 ]]; then return 0; fi
    smsg -t get_tree | jq -r --arg re "$re" '
      [.. | objects | select(.type == "con")
        | select((.name // "") | test($re; "i"))
        | {out: .output, x: .rect.x, y: .rect.y, w: .rect.width, h: .rect.height}]
      | (map(select(.w > 0 and .h > 0)) | .[0] // empty)
      | "\(.out) \(.x) \(.y) \(.w) \(.h)"'
}

window_exists() {
    local re="$1"
    smsg -t get_tree | grep -qiE "\"name\": \"[^\"]*($re)" || return 1
    return 0
}

capture_qr() {
    local geom out
    geom="$(find_window "$QR_TITLE_RE")"
    if [[ -n "$geom" ]]; then
        read -r out x y w h <<< "$geom"
        # grim -g 是全局坐标，headless 单输出原点即 0,0，直接可用
        grim -g "${x},${y} ${w}x${h}" "$QR_TMP" 2>/dev/null || return 1
    else
        # 无 jq：整屏兜底（二维码也在图里，手机照样能扫）
        out="$(smsg -t get_outputs | grep -o '"name": *"[^"]*"' | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
        [[ -n "$out" ]] || out="HEADLESS-1"
        grim -o "$out" "$QR_TMP" 2>/dev/null || return 1
    fi
    mv -f "$QR_TMP" "$QR_FILE"      # 原子替换，扫码端永远读到完整文件
}

# ---- 主循环：截二维码 → 等登录 ------------------------------------------------
QR_SEEN=0
START=$(date +%s)
log "每 ${POLL_INTERVAL}s 截取二维码到 $QR_FILE，登录成功后写 $LOGIN_STATE"
while true; do
    if window_exists "$QR_TITLE_RE"; then
        QR_SEEN=1
        capture_qr || log "截图失败，下一轮重试"
    elif [[ "$QR_SEEN" == 1 ]] && window_exists "$MAIN_TITLE_RE"; then
        # 登录窗口消失 + 主窗口出现 → 登录成功
        date +%s > "$LOGIN_STATE"
        log "登录成功！二维码会话已就绪。"
        log "后续自动化: source $ENV_FILE 后运行 wechatauto.linux_ui / linux_key"
        break
    elif [[ "$QR_SEEN" == 1 ]]; then
        # 登录窗没了但主窗没等到：可能标题正则不匹配，超时兜底提示
        if (( $(date +%s) - START > LOGOUT_TIMEOUT )); then
            log "登录窗口已消失但未匹配到主窗口标题（MAIN_TITLE_RE=$MAIN_TITLE_RE）。"
            log "微信可能已登录；请人工确认后把 login.state 手动建好再继续。"
            break
        fi
    fi
    if (( $(date +%s) - START > LOGOUT_TIMEOUT + 60 )); then
        die "超时退出（${LOGOUT_TIMEOUT}s 内未完成扫码登录）。"
    fi
    sleep "$POLL_INTERVAL"
done

# ---- 保持会话 ----------------------------------------------------------------
log "会话保持运行中（sway pid=$SWAY_PID, 微信 pid=${WECHAT_PID:-?}）。Ctrl+C 退出并清理。"
wait "$WECHAT_PID" 2>/dev/null || true
log "微信进程退出，清理会话。"
