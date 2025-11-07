#!/usr/bin/env python3
"""
Create a Bluetooth PAN hotspot (NAP) on Ubuntu/BlueZ with a custom device name.

The script:
  * powers on the Bluetooth adapter and sets it discoverable/pairable indefinitely
  * sets a custom alias so phones/computers can find your hotspot quickly
  * brings up a bridge interface (pan0) with a private subnet
  * starts dnsmasq to hand out IPv4 addresses to connected devices
  * enables IPv4 forwarding and configures iptables MASQUERADE to share your internet
  * runs bt-network in server mode to accept incoming NAP connections

Dependencies (Ubuntu):
    sudo apt install bluez bluez-tools dnsmasq iproute2 iptables

Run as root:
    sudo python3 bluetooth_hotspot.py --name MyHotspot

Stop with Ctrl+C and the script will revert any network changes.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import List, Optional


class CommandError(RuntimeError):
    pass


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("请以 root 权限运行（例如 sudo python3 bluetooth_hotspot.py --name MyHotspot）")


def which(cmd: str) -> Path:
    path = shutil.which(cmd)
    if not path:
        raise SystemExit(f"找不到命令 {cmd!r}，请先安装对应软件包。")
    return Path(path)


def run(cmd: List[str], *, check: bool = True, input_text: Optional[str] = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        message = stdout or stderr or f"命令 {cmd} 失败，返回码 {result.returncode}"
        raise CommandError(message)
    return result


def detect_upstream_interface() -> str:
    result = run(["ip", "route", "show", "default"], check=False)
    for line in result.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            try:
                idx = parts.index("dev")
                return parts[idx + 1]
            except (ValueError, IndexError):
                continue
    raise SystemExit("无法自动检测外网接口，请使用 --upstream 手动指定。")


class IptablesManager:
    def __init__(self, subnet: ipaddress.IPv4Network, upstream: str) -> None:
        self.upstream = upstream
        self.subnet = subnet
        self.binary = self._detect_binary()
        self.rules: List[List[str]] = []

    @staticmethod
    def _detect_binary() -> str:
        for candidate in ("iptables-nft", "iptables-legacy", "iptables"):
            if shutil.which(candidate):
                return candidate
        raise SystemExit("找不到 iptables，请安装 netfilter 工具。")

    def add_rules(self, pan_iface: str) -> None:
        subnet_str = str(self.subnet)
        self._append_rule(["-t", "nat", "-A", "POSTROUTING", "-s", subnet_str, "-o", self.upstream, "-j", "MASQUERADE"])
        self._append_rule(["-A", "FORWARD", "-i", self.upstream, "-o", pan_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        self._append_rule(["-A", "FORWARD", "-i", pan_iface, "-o", self.upstream, "-j", "ACCEPT"])

    def remove_rules(self) -> None:
        for rule in reversed(self.rules):
            delete_rule = rule.copy()
            if "-A" in delete_rule:
                idx = delete_rule.index("-A")
                delete_rule[idx] = "-D"
            try:
                run([self.binary, *delete_rule], check=False)
            except CommandError:
                pass
        self.rules.clear()

    def _append_rule(self, args: List[str]) -> None:
        run([self.binary, *args])
        self.rules.append(args)


def ensure_sysctl_forwarding() -> str:
    current = run(["sysctl", "-n", "net.ipv4.ip_forward"]).stdout.strip()
    if current != "1":
        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    return current


def restore_sysctl_forwarding(previous: str) -> None:
    if previous != "1":
        run(["sysctl", "-w", f"net.ipv4.ip_forward={previous}"], check=False)


def ensure_bridge(pan_iface: str, subnet: ipaddress.IPv4Network) -> None:
    existing = run(["ip", "-o", "link", "show"], check=False).stdout
    if f"{pan_iface}:" not in existing:
        run(["ip", "link", "add", "name", pan_iface, "type", "bridge"])
    run(["ip", "addr", "flush", "dev", pan_iface], check=False)
    run(["ip", "addr", "add", f"{subnet.network_address + 1}/{subnet.prefixlen}", "dev", pan_iface])
    run(["ip", "link", "set", pan_iface, "up"])


def remove_bridge(pan_iface: str) -> None:
    run(["ip", "link", "set", pan_iface, "down"], check=False)
    run(["ip", "link", "delete", pan_iface, "type", "bridge"], check=False)


def configure_bluetooth(name: str) -> None:
    run(["rfkill", "unblock", "bluetooth"], check=False)
    run(["systemctl", "start", "bluetooth"])
    commands = [
        "power on",
        "discoverable on",
        "discoverable-timeout 0",
        "pairable on",
        "pairable-timeout 0",
        "agent NoInputNoOutput",
        "default-agent",
        f"system-alias {name}",
        f"set-alias {name}",
    ]
    run(["bluetoothctl"], input_text="\n".join(commands) + "\n")


def start_dnsmasq(pan_iface: str, subnet: ipaddress.IPv4Network, lease_range: str) -> tuple[subprocess.Popen[str], Path]:
    config = tempfile.NamedTemporaryFile("w", delete=False, prefix="dnsmasq-bluetooth-", suffix=".conf")
    config.write(
        "\n".join(
            [
                f"interface={pan_iface}",
                "bind-interfaces",
                "no-hosts",
                "no-resolv",
                "dhcp-authoritative",
                f"dhcp-range={lease_range}",
                f"dhcp-option=option:router,{subnet.network_address + 1}",
                "log-queries",
                "log-dhcp",
            ]
        )
    )
    config.flush()
    config.close()

    dnsmasq_bin = which("dnsmasq")
    proc = subprocess.Popen(
        [
            str(dnsmasq_bin),
            "--keep-in-foreground",
            "--conf-file",
            config.name,
            "--log-facility=-",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    return proc, Path(config.name)


def stream_subprocess_output(proc: subprocess.Popen[str], prefix: str) -> threading.Thread:
    def _target() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            print(f"[{prefix}] {line.rstrip()}")

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    return thread


def start_bt_network_server(pan_iface: str) -> subprocess.Popen[bytes]:
    bt_network = which("bt-network")
    return subprocess.Popen([str(bt_network), "-s", "nap", pan_iface])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="启动一个蓝牙 PAN 热点（NAP）并共享上网。")
    parser.add_argument("--name", required=True, help="对外显示的蓝牙热点名称")
    parser.add_argument("--pan-iface", default="pan0", help="内部桥接接口名称 (默认 pan0)")
    parser.add_argument(
        "--subnet",
        default="192.168.50.0/24",
        help="为热点分配的 IPv4 子网 (默认 192.168.50.0/24)",
    )
    parser.add_argument(
        "--lease-range",
        default="192.168.50.10,192.168.50.100,12h",
        help="DHCP 地址池 (默认 192.168.50.10,192.168.50.100,12h)",
    )
    parser.add_argument(
        "--upstream",
        default=None,
        help="共享上网的外网接口 (默认自动检测默认路由)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    require_root()

    try:
        subnet = ipaddress.IPv4Network(args.subnet, strict=False)
    except ValueError as exc:
        raise SystemExit(f"无效的子网: {exc}")

    upstream_iface = args.upstream or detect_upstream_interface()
    print(f"外网接口: {upstream_iface}")

    configure_bluetooth(args.name)
    ensure_bridge(args.pan_iface, subnet)

    iptables_mgr = IptablesManager(subnet, upstream_iface)
    iptables_mgr.add_rules(args.pan_iface)

    previous_forward = ensure_sysctl_forwarding()

    dnsmasq_proc, dnsmasq_conf = start_dnsmasq(args.pan_iface, subnet, args.lease_range)
    dnsmasq_thread = stream_subprocess_output(dnsmasq_proc, "dnsmasq")

    bt_proc = start_bt_network_server(args.pan_iface)
    print("✅ 蓝牙热点已准备，等待设备连接。")
    print("提示：首次连接需要在手机/电脑上配对并允许使用网络。")

    stop_event = threading.Event()

    def _handle_signal(signum: int, _frame) -> None:
        print(f"\n收到信号 {signum}，正在清理资源…")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _handle_signal)

    try:
        while not stop_event.is_set():
            if bt_proc.poll() is not None:
                raise SystemExit("bt-network 服务意外退出，请检查蓝牙配置。")
            if dnsmasq_proc.poll() is not None:
                raise SystemExit("dnsmasq 已退出，请检查日志。")
            time.sleep(1.0)
    finally:
        bt_proc.terminate()
        try:
            bt_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            bt_proc.kill()

        dnsmasq_proc.terminate()
        try:
            dnsmasq_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dnsmasq_proc.kill()
        dnsmasq_thread.join(timeout=2)

        if dnsmasq_conf.exists():
            dnsmasq_conf.unlink(missing_ok=True)

        iptables_mgr.remove_rules()
        restore_sysctl_forwarding(previous_forward)
        remove_bridge(args.pan_iface)
        print("🛑 蓝牙热点已停止。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
