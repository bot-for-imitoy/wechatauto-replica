"""wechatauto —— 微信客户端（非网页版）自动化。

Windows：基于 UIAutomation 驱动当前微信4.x客户端，可实现简单的发送、
接收微信消息，编写简单的微信机器人。

Linux：``wechatauto.db`` 纯读库路径完全可用（``WeChatDB`` /
``auto_detect_db_dir`` / ``list_accounts`` / ``GroupMemberWatcher``）；
密钥提取走 ``wechatauto.linux_key``（一次性 root 内存扫描，密钥为静态值，
成功一次后永久缓存）；UI 自动化后端见 ``wechatauto.linux_ui``。
Windows 专属符号（WeChat / WeChatGUI / Moment 等）在 Linux 上延迟导入：
只有真正访问它们才会报错，并给出指向 Linux 替代路径的说明。
"""

from __future__ import annotations

import sys

from .param import WxParam, WxResponse, PROJECT_NAME
from .logger import wxlog
from .exceptions import (
    NetWorkError,
    WechatautoError,
    WechatautoNoteLoadTimeoutError,
    WechatautoUINotFoundError,
    WechatautoNotLoggedInError,
)
from .utils.lock import LockManager, uilock

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    # Windows：与原版行为完全一致，全部顶层导入
    from .wx import WeChat, Chat, Listener
    from . import rhythm
    from .moment import Moment, MomentDB
    from .moment_observer import MomentObserver
    from .db import WeChatDB, GroupMemberWatcher, auto_detect_db_dir, list_accounts
    from .media import MediaDownloader
    from .recall import RecallGuard
    from .guia import (
        WeChatGUI,
        quick_send,
        quick_send_file,
        quick_send_image,
        quick_reply,
        WinInput,
        ScreenOCR,
    )
    from .msgs import (
        Message,
        BaseMessage,
        HumanMessage,
        TextMessage,
        ImageMessage,
        VideoMessage,
        VoiceMessage,
        FileMessage,
        QuoteMessage,
        LinkMessage,
        LocationMessage,
        PersonalCardMessage,
        OtherMessage,
        SystemMessage,
        FriendMessage,
        SelfMessage,
        parse_msg,
    )
else:
    # Linux：只直接导入纯读库与纯数据模块；Windows 专属符号延迟导入
    from .db import WeChatDB, GroupMemberWatcher, auto_detect_db_dir, list_accounts

__version__ = "1.2.5.1"

_WIN_ONLY_EXPORTS = {
    "WeChat": (".wx", "WeChat"),
    "Chat": (".wx", "Chat"),
    "Listener": (".wx", "Listener"),
    "rhythm": ("wechatauto.rhythm", None),
    "Moment": (".moment", "Moment"),
    "MomentDB": (".moment", "MomentDB"),
    "MomentObserver": (".moment_observer", "MomentObserver"),
    "MediaDownloader": (".media", "MediaDownloader"),
    "RecallGuard": (".recall", "RecallGuard"),
    "WeChatGUI": (".guia", "WeChatGUI"),
    "quick_send": (".guia", "quick_send"),
    "quick_send_file": (".guia", "quick_send_file"),
    "quick_send_image": (".guia", "quick_send_image"),
    "quick_reply": (".guia", "quick_reply"),
    "WinInput": (".guia", "WinInput"),
    "ScreenOCR": (".guia", "ScreenOCR"),
    "Message": (".msgs", "Message"),
    "BaseMessage": (".msgs", "BaseMessage"),
    "HumanMessage": (".msgs", "HumanMessage"),
    "TextMessage": (".msgs", "TextMessage"),
    "ImageMessage": (".msgs", "ImageMessage"),
    "VideoMessage": (".msgs", "VideoMessage"),
    "VoiceMessage": (".msgs", "VoiceMessage"),
    "FileMessage": (".msgs", "FileMessage"),
    "QuoteMessage": (".msgs", "QuoteMessage"),
    "LinkMessage": (".msgs", "LinkMessage"),
    "LocationMessage": (".msgs", "LocationMessage"),
    "PersonalCardMessage": (".msgs", "PersonalCardMessage"),
    "OtherMessage": (".msgs", "OtherMessage"),
    "SystemMessage": (".msgs", "SystemMessage"),
    "FriendMessage": (".msgs", "FriendMessage"),
    "SelfMessage": (".msgs", "SelfMessage"),
    "parse_msg": (".msgs", "parse_msg"),
}


def __getattr__(name: str):
    """PEP 562 延迟导入：Windows 专属符号只在被访问时才加载其模块。

    Linux 上访问这些符号会得到带指引的 ``PlatformNotSupportedError``，
    而不是让 ``import wechatauto`` 整体失败。
    """
    if IS_WINDOWS and name in _WIN_ONLY_EXPORTS:
        mod_name, attr = _WIN_ONLY_EXPORTS[name]
        import importlib

        mod = importlib.import_module(mod_name, __name__)
        val = mod if attr is None else getattr(mod, attr)
        globals()[name] = val          # 缓存，后续访问不再走 __getattr__
        return val
    if name in _WIN_ONLY_EXPORTS:
        hint = {
            "WeChat": "wechatauto.linux_ui.WeChatLinux（发送）+ wechatauto.db.WeChatDB（读取）",
        }.get(
            name,
            "wechatauto.db.WeChatDB（读取）或 wechatauto.linux_ui（Linux UI 后端）",
        )
        from .utils import PlatformNotSupportedError
        raise PlatformNotSupportedError(
            f"符号 {name} 依赖 Windows UIA/win32 工具集。"
            f"Linux 上请改用 {hint}。"
        )
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "WeChat",
    "Chat",
    "Listener",
    "WeChatDB",
    "GroupMemberWatcher",
    "auto_detect_db_dir",
    "list_accounts",
    "MediaDownloader",
    "RecallGuard",
    "WeChatGUI",
    "quick_send",
    "quick_send_file",
    "quick_send_image",
    "quick_reply",
    "WinInput",
    "ScreenOCR",
    "WxParam",
    "WxResponse",
    "wxlog",
    "Moment",
    "MomentDB",
    "MomentObserver",
    "rhythm",
    "LockManager",
    "uilock",
    "WechatautoError",
    "NetWorkError",
    "WechatautoUINotFoundError",
    "WechatautoNoteLoadTimeoutError",
    "WechatautoNotLoggedInError",
    "Message",
    "BaseMessage",
    "HumanMessage",
    "TextMessage",
    "ImageMessage",
    "VideoMessage",
    "VoiceMessage",
    "FileMessage",
    "QuoteMessage",
    "LinkMessage",
    "LocationMessage",
    "PersonalCardMessage",
    "OtherMessage",
    "SystemMessage",
    "FriendMessage",
    "SelfMessage",
    "parse_msg",
    "PROJECT_NAME",
    "__version__",
    "IS_WINDOWS",
]
