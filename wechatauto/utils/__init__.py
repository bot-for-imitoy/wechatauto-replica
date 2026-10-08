"""工具子包：按平台分发。

- Windows：导入完整的 win32 工具集（窗口枚举、剪贴板、句柄定位等），
  行为与原版完全一致；
- Linux / 其它平台：只导入跨平台的 UI 锁；win32 工具不可用，任何触碰
  窗口系统的调用都会得到明确的 ``PlatformNotSupportedError``，而不是
  import 阶段的 ``ModuleNotFoundError``——这样 ``import wechatauto.db``
  这类纯读库用法在 Linux 上完全可用（Linux 支持见 ``wechatauto/linux_key.py``）。
"""

from __future__ import annotations

import sys

IS_WINDOWS = sys.platform == "win32"

from wechatauto.utils.lock import LockManager, uilock

__all__ = ["LockManager", "uilock", "IS_WINDOWS"]

if IS_WINDOWS:
    from wechatauto.utils.win32 import (
        GetAllWindows,
        GetCursorWindow,
        GetPathByHwnd,
        FindWindow,
        FindWinEx,
        SetClipboardText,
        SetClipboardFiles,
        SetClipboardData,
        ReadClipboardData,
        PasteFile,
        get_windows_by_pid,
        GetText,
        GetAllWindowExs,
    )

    __all__ += [
        "GetAllWindows",
        "GetCursorWindow",
        "GetPathByHwnd",
        "FindWindow",
        "FindWinEx",
        "SetClipboardText",
        "SetClipboardFiles",
        "SetClipboardData",
        "ReadClipboardData",
        "PasteFile",
        "get_windows_by_pid",
        "GetText",
        "GetAllWindowExs",
    ]
else:

    class PlatformNotSupportedError(RuntimeError):
        """当前平台不提供 win32 工具集（窗口枚举/剪贴板等）。

        Linux 上请使用 ``wechatauto.db``（纯读库）与 ``wechatauto.linux_ui``
        （Linux UI 后端），不要调用本模块导出的 win32 函数。
        """

        def __init__(self, name: str = ""):
            self.name = name
            hint = (
                f"wechatauto.utils.{name} 仅在 Windows 上可用。"
                if name
                else "该 win32 工具仅在 Windows 上可用。"
            )
            super().__init__(
                hint + "Linux 上请改用 wechatauto.db（读库）或 "
                "wechatauto.linux_ui（Linux UI 后端）。"
            )

    def _unsupported(name: str):
        def _raise(*args, **kwargs):
            raise PlatformNotSupportedError(name)

        _raise.__name__ = name
        _raise.__qualname__ = name
        _raise.__doc__ = f"（仅 Windows）原 win32 工具 {name}。Linux 上调用会抛错。"
        return _raise

    for _name in (
        "GetAllWindows",
        "GetCursorWindow",
        "GetPathByHwnd",
        "FindWindow",
        "FindWinEx",
        "SetClipboardText",
        "SetClipboardFiles",
        "SetClipboardData",
        "ReadClipboardData",
        "PasteFile",
        "get_windows_by_pid",
        "GetText",
        "GetAllWindowExs",
    ):
        globals()[_name] = _unsupported(_name)

    __all__ += [
        "GetAllWindows",
        "GetCursorWindow",
        "GetPathByHwnd",
        "FindWindow",
        "FindWinEx",
        "SetClipboardText",
        "SetClipboardFiles",
        "SetClipboardData",
        "ReadClipboardData",
        "PasteFile",
        "get_windows_by_pid",
        "GetText",
        "GetAllWindowExs",
        "PlatformNotSupportedError",
    ]
