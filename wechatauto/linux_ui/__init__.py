# -*- coding: utf-8 -*-
"""Linux UI 自动化后端（AT-SPI2 + Wayland/X11 输入注入）。

与 Windows 版的对应关系：

    Windows                          Linux
    -----------------------------    -----------------------------
    UIA 控件树（uiautomation）    →  AT-SPI2 无障碍树（Atspi）
    剪贴板/键盘（win32）          →  wl-copy/wl-clipboard + wtype（Wayland）
                                       xclip + xdotool（X11）
    坐标+OCR 兜底（guia）         →  grim 截图 + 同款 OCR 路线（可选）
    WeChat 编排逻辑（wx.py）      →  WeChatLinux：读库用 WeChatDB（同一套），
                                       界面驱动换成 AT-SPI2，方法名保持一致

诚实声明：控件选择器（搜索框/会话列表/输入框在无障碍树中的路径）需要按
真机 AT-SPI 树校准，本模块内置的默认值来自对微信 Linux 客户端的合理推断，
**未经真机验证**。请先运行::

    python -m wechatauto.linux_ui.probe > tree.json

把真实树结构反馈进来（或自行修改 calibration），校准后编排逻辑即可复用。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from wechatauto.utils.lock import uilock

# 校准文件：覆盖默认选择器，免改代码
_CALIB_PATHS = [
    os.path.join(os.path.expanduser("~"), ".config", "wechatauto_linux",
                 "calibration.json"),
    os.path.join(os.path.dirname(__file__), "calibration.json"),
]

DEFAULT_CALIBRATION: Dict[str, Any] = {
    # 微信主窗口识别（app_id / 名称包含，大小写不敏感）
    "window_match": ["wechat", "weixin", "微信"],
    # 搜索框：名称或占位符包含任一关键字（Role: text entry）
    "search_box_keys": ["搜索", "search"],
    # 输入框：名称/描述包含任一关键字
    "input_box_keys": ["输入", "发送消息", "input"],
    # 发送按钮
    "send_button_keys": ["发送", "send"],
    # 发送前回读校验比率（与 WxParam.SEND_CONTENT_RATIO 同义）
    "send_content_ratio": 0.6,
    # 打开会话后等待界面就绪的秒数
    "settle_seconds": 1.2,
}


def load_calibration() -> Dict[str, Any]:
    calib = dict(DEFAULT_CALIBRATION)
    for p in _CALIB_PATHS:
        if os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as f:
                    calib.update(json.load(f))
                break
            except (OSError, json.JSONDecodeError):
                continue
    return calib


# ---------------------------------------------------------------------------
# AT-SPI2 访问层
# ---------------------------------------------------------------------------
class AtspiUnavailable(RuntimeError):
    """系统缺少 AT-SPI2 Python 绑定或无可用会话。"""


def _atspi():
    try:
        import gi  # noqa: F401  (PyGObject: 系统包 python3-gi)
        gi.require_version("Atspi", "2.0")
        from gi.repository import Atspi  # noqa: F401
        return Atspi
    except (ImportError, ValueError) as exc:
        raise AtspiUnavailable(
            "需要 AT-SPI2 Python 绑定。Debian/Ubuntu: sudo apt install "
            "python3-gi gir1.2-atspi-2.0 at-spi2-core；Fedora: sudo dnf install "
            "python3-gobject at-spi2-core。Wayland 会话需在桌面登录环境下运行。"
        ) from exc


def walk(obj: Any, depth: int = 0, max_depth: int = 25):
    """先序遍历 AT-SPI 树，yield (节点, 深度)。"""
    atspi = _atspi()
    yield obj, depth
    if depth >= max_depth:
        return
    try:
        n = obj.get_child_count()
    except Exception:
        return
    for i in range(n):
        try:
            child = obj.get_child_at_index(i)
        except Exception:
            continue
        if child is None:
            continue
        yield from walk(child, depth + 1, max_depth)


class WeChatLinux:
    """微信 Linux 客户端自动化（读库 + AT-SPI2 界面驱动）。

    方法名与 Windows 版 ``wechatauto.wx.WeChat`` 对齐的子集：
    ``SendMsg`` / ``ChatList`` / ``CurrentChat`` / ``open_chat``。
    读取能力（``db`` 属性）与 Windows 版完全同源。
    """

    def __init__(self, db_dir: Optional[str] = None, **db_kwargs):
        self.calib = load_calibration()
        self._atspi = _atspi()
        self._window = self._find_main_window()
        if self._window is None:
            raise RuntimeError(
                "未找到微信主窗口。请确认微信已启动（wayland/X11 桌面会话内），"
                "或先用 python -m wechatauto.linux_ui.probe 检查无障碍树。")
        self.db = None
        if db_dir or db_kwargs:
            from wechatauto.db import WeChatDB
            self.db = WeChatDB(db_dir=db_dir, **db_kwargs)

    # -- 窗口与节点 ------------------------------------------------------
    def _match_name(self, node: Any, keys: List[str]) -> bool:
        name = (node.get_name() or "").lower()
        desc = ""
        try:
            desc = (node.get_description() or "").lower()
        except Exception:
            pass
        return any(k.lower() in name or k.lower() in desc for k in keys)

    def _find_main_window(self) -> Optional[Any]:
        atspi = self._atspi
        desktop = atspi.get_desktop(0)
        matches = [n.lower() for n in self.calib["window_match"]]
        for app_i in range(desktop.get_child_count()):
            app = desktop.get_child_at_index(app_i)
            try:
                app_name = (app.get_name() or "").lower()
            except Exception:
                continue
            if not any(m in app_name for m in matches):
                continue
            for i in range(app.get_child_count()):
                frame = app.get_child_at_index(i)
                try:
                    if frame.get_role_name() in ("frame", "window", "dialog"):
                        return frame
                except Exception:
                    continue
        return None

    def _find_node(self, keys: List[str], roles: Optional[List[str]] = None,
                   max_depth: int = 18) -> Optional[Any]:
        roles = roles or []
        for node, _depth in walk(self._window, max_depth=max_depth):
            try:
                role = node.get_role_name()
            except Exception:
                continue
            if roles and role not in roles:
                continue
            if self._match_name(node, keys):
                return node
        return None

    # -- 会话与发送（编排逻辑与 Windows 版一致）--------------------------
    def open_chat(self, who: str, timeout: float = 20.0) -> bool:
        """通过搜索框打开会话：点搜索框 → 输入关键字 → 回车选第一项。"""
        inp = self._find_node(self.calib["search_box_keys"],
                              roles=["text", "entry"])
        if inp is None:
            raise RuntimeError(
                "未在无障碍树中找到搜索框——选择器需按真机校准"
                "（python -m wechatauto.linux_ui.probe 查看树）。")
        self._click_node(inp)
        time.sleep(0.3)
        self._type_text(who)
        time.sleep(self.calib["settle_seconds"])
        self._press("Return")
        time.sleep(self.calib["settle_seconds"])
        return self._is_open(who, timeout)

    def _is_open(self, who: str, timeout: float) -> bool:
        """读主窗口标题/当前会话名判断是否打开成功（与 wx.open_chat 同思路）。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                title = (self._window.get_name() or "").lower()
            except Exception:
                title = ""
            if who.lower() in title:
                return True
            time.sleep(0.4)
        return False

    def CurrentChat(self) -> Optional[str]:
        node = self._find_node(self.calib["input_box_keys"],
                               roles=["text", "entry"])
        if node is None:
            return None
        return node.get_name()

    def ChatList(self) -> List[Dict[str, Any]]:
        """会话列表：优先读库（与 Windows 版一致，界面只做兜底）。"""
        if self.db is not None:
            return [dict(row) for row in self.db.get_sessions(limit=50)]
        return []

    @uilock
    def SendMsg(self, msg: str, who: Optional[str] = None,
                verify: bool = True) -> bool:
        """发送文本：打开会话 → 粘贴 → 回读校验 → 回车（复用原版防呆设计）。"""
        if who and not self._is_open(who, timeout=0):
            if not self.open_chat(who):
                raise RuntimeError(f"打不开会话: {who}")
        box = self._find_node(self.calib["input_box_keys"],
                              roles=["text", "entry"])
        if box is None:
            raise RuntimeError("未找到输入框（选择器需校准）。")
        self._click_node(box)
        self._paste_text(msg)
        time.sleep(0.2)
        if verify:
            current = self._read_text(box) or ""
            ratio = self.calib["send_content_ratio"]
            folded = self._fold_emoji(msg)
            read = self._fold_emoji(current)
            score = self._ratio(folded, read)
            if score < ratio:
                self._press("ctrl+a")
                self._press("Delete")
                raise RuntimeError(
                    f"发送前回读校验未通过（{score:.2f} < {ratio}），"
                    "已清空输入框，未发送。")
        self._press("Return")
        return True

    # -- 输入注入（Wayland: wtype/wl-copy；X11: xdotool/xclip）-----------
    def _session_tool(self) -> str:
        if os.environ.get("WAYLAND_DISPLAY"):
            for t in ("wtype", "ydotool"):
                if shutil.which(t):
                    return t
            raise RuntimeError(
                "Wayland 会话需要 wtype（wlroots）或 ydotool："
                "sudo apt install wtype / sudo pacman -S wtype")
        if os.environ.get("DISPLAY") and shutil.which("xdotool"):
            return "xdotool"
        raise RuntimeError("未检测到 Wayland/X11 会话与输入注入工具。")

    def _clipboard_tool(self) -> str:
        for t in ("wl-copy", "xclip", "xsel"):
            if shutil.which(t):
                return t
        raise RuntimeError("需要 wl-clipboard（wl-copy）或 xclip 以支持粘贴发送。")

    def _run(self, cmd: List[str], **kw) -> None:
        subprocess.run(cmd, check=True, **kw)

    def _click_node(self, node: Any) -> None:
        """优先 AT-SPI Action.do_action(0)；没有动作再按坐标点击。"""
        try:
            act = node.query_action()
            if act and act.get_n_actions() > 0:
                act.do_action(0)
                return
        except Exception:
            pass
        try:
            comp = node.query_component()
            x, y, w, h = comp.get_extents(0)
            self._pointer_click(x + w // 2, y + h // 2)
        except Exception as exc:
            raise RuntimeError(f"节点无法点击: {exc!r}") from exc

    def _pointer_click(self, x: int, y: int) -> None:
        tool = self._session_tool()
        if tool == "wtype":
            # wtype 不做指针；指针用 wlrctl（可选）或交给 AT-SPI 动作
            if shutil.which("wlrctl"):
                self._run(["wlrctl", "pointer", "click", f"{x},{y}"])
                return
            raise RuntimeError("wtype 无法移动指针；请安装 wlrctl 或确保节点"
                               "暴露 AT-SPI Action。")
        if tool == "ydotool":
            self._run(["ydotool", "mousemove", "--absolute", "-x", str(x),
                       "-y", str(y), "-c", "1"])
            return
        self._run(["xdotool", "mousemove", str(x), str(y), "click", "1"])

    def _type_text(self, text: str) -> None:
        tool = self._session_tool()
        if tool == "wtype":
            self._run(["wtype", "-s", "30", text])
        elif tool == "ydotool":
            self._run(["ydotool", "type", "--", text])
        else:
            self._run(["xdotool", "type", "--delay", "30", "--", text])

    def _paste_text(self, text: str) -> None:
        clip = self._clipboard_tool()
        if clip == "wl-copy":
            self._run(["wl-copy", text])
        elif clip == "xclip":
            self._run(["xclip", "-selection", "clipboard"], input=text.encode())
        else:
            self._run(["xsel", "--clipboard", "--input"], input=text.encode())
        self._press("ctrl+v")

    def _press(self, combo: str) -> None:
        tool = self._session_tool()
        if tool == "wtype":
            parts = combo.split("+")
            args = []
            for k in parts[:-1]:
                args += ["-M", k]
            args += ["-k", parts[-1]]
            for k in parts[:-1]:
                args += ["-m", k]
            self._run(["wtype"] + args)
        elif tool == "ydotool":
            self._run(["ydotool", "key", combo])
        else:
            self._run(["xdotool", "key", combo])

    # -- 文本读取与比对（与 Windows 版回读校验同款口径）------------------
    @staticmethod
    def _read_text(node: Any) -> Optional[str]:
        try:
            txt = node.query_text()
            return txt.get_text(0, txt.get_character_count())
        except Exception:
            return None

    @staticmethod
    def _fold_emoji(s: str) -> str:
        # 微信把 [表情] 折叠成单个 U+FFFC；比对前两侧统一折叠（同 v1.2.5 口径）
        import re
        return re.sub(r"\[[^\[\]]{1,8}\]", "\U0001fffc", s or "")

    @staticmethod
    def _ratio(a: str, b: str) -> float:
        if not a:
            return 0.0
        common = sum(1 for x, y in zip(a, b) if x == y)
        return common / max(len(a), len(b))


def probe_tree(max_depth: int = 20, out_path: Optional[str] = None) -> str:
    """导出微信窗口的无障碍树（校准选择器用），返回 JSON 字符串。"""
    calib = load_calibration()
    atspi = _atspi()
    desktop = atspi.get_desktop(0)
    tree: Dict[str, Any] = {}

    def dump(node: Any, depth: int) -> Dict[str, Any]:
        d: Dict[str, Any] = {"role": node.get_role_name(),
                             "name": node.get_name()}
        try:
            d["desc"] = node.get_description()
        except Exception:
            pass
        try:
            txt = node.query_text()
            text = txt.get_text(0, min(txt.get_character_count(), 200))
            if text:
                d["text"] = text
        except Exception:
            pass
        if depth < max_depth:
            kids = []
            try:
                n = node.get_child_count()
            except Exception:
                n = 0
            for i in range(n):
                try:
                    kids.append(dump(node.get_child_at_index(i), depth + 1))
                except Exception:
                    continue
            if kids:
                d["children"] = kids
        return d

    for i in range(desktop.get_child_count()):
        app = desktop.get_child_at_index(i)
        name = (app.get_name() or "").lower()
        if any(m in name for m in calib["window_match"]):
            tree = dump(app, 0)
            break
    js = json.dumps(tree, ensure_ascii=False, indent=2)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(js)
    return js
