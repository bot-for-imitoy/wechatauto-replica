# -*- coding: utf-8 -*-
"""导出微信 Linux 客户端的无障碍树，用于校准 linux_ui 的选择器。

用法（在微信已启动的桌面会话里）::

    python -m wechatauto.linux_ui.probe                # 打印到 stdout
    python -m wechatauto.linux_ui.probe -o tree.json   # 同时落盘

拿到树后，把搜索框/输入框/发送按钮对应的 name 写进
~/.config/wechatauto_linux/calibration.json，例如::

    {"search_box_keys": ["搜索"], "input_box_keys": ["输入"], "send_button_keys": ["发送"]}
"""
import argparse
import sys

from wechatauto.linux_ui import probe_tree


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m wechatauto.linux_ui.probe")
    ap.add_argument("-o", "--out", help="同时写入该 JSON 文件")
    ap.add_argument("--depth", type=int, default=20, help="遍历深度上限")
    args = ap.parse_args()
    try:
        js = probe_tree(max_depth=args.depth, out_path=args.out)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(js)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
