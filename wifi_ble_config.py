"""BLE peripheral that accepts Wi-Fi credentials over GATT and replies with connection status.

This implementation uses the `bluez_peripheral` helper library so that the device
acts as a proper BLE peripheral on Linux (BlueZ).  Compared to the previous
approach that only scanned for the local adapter, this script actually advertises
the custom service and waits for a connected central to write credentials.

Requirements:
    pip install bluez-peripheral
    sudo apt install network-manager (for nmcli)

Ensure the Bluetooth adapter is not blocked and the BlueZ daemon is running:
    sudo rfkill unblock bluetooth
    sudo systemctl start bluetooth

Run the script with sufficient privileges to let BlueZ register the GATT service
and advertisement (typically sudo):
    sudo python3 wifi_ble_config.py
"""

from __future__ import annotations

import asyncio
import json
import signal
import socket
import subprocess
from dataclasses import dataclass
from typing import Optional

from bluez_peripheral import Advertisement, AdvertisingIncludes, PacketType
from bluez_peripheral.agent import NoIoAgent
from bluez_peripheral.gatt.characteristic import (
    CharacteristicFlags,
    CharacteristicWriteOptions,
    characteristic,
)
from bluez_peripheral.gatt.service import Service
from bluez_peripheral.util import Adapter, get_message_bus, is_bluez_available


DEVICE_NAME = "WiFi-Config"
SERVICE_UUID = "0000ffe1-0000-1000-8000-00805f9b34fb"
CHARACTERISTIC_UUID = "0000ffe2-0000-1000-8000-00805f9b34fb"
ADVERT_PATH = "/com/spacecheese/wifi_config/advert0"


@dataclass(slots=True)
class WiFiResult:
    success: bool
    message: str
    ip: Optional[str] = None

    def to_payload(self) -> bytes:
        body = {"success": self.success, "message": self.message}
        if self.ip:
            body["ip"] = self.ip
        return json.dumps(body, ensure_ascii=False).encode()


def _connect_wifi(ssid: str, password: str, hidden: bool) -> WiFiResult:
    """Invoke NetworkManager (nmcli) to connect to the requested Wi-Fi network."""

    if not ssid:
        return WiFiResult(False, "缺少 ssid")

    cmd = [
        "nmcli",
        "device",
        "wifi",
        "connect",
        ssid,
    ]

    if password:
        cmd.extend(["password", password])

    if hidden:
        cmd.extend(["hidden", "yes"])

    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    if completed.returncode != 0:
        msg = completed.stdout.strip() or completed.stderr.strip() or "连接失败"
        return WiFiResult(False, msg)

    ip = _current_ipv4()
    return WiFiResult(True, "Wi-Fi 已连接", ip=ip or "无有效IP")


def _current_ipv4() -> Optional[str]:
    """Determine the current outbound IPv4 address (best effort)."""

    sock: Optional[socket.socket] = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    except OSError:
        ip = None
    finally:
        if sock is not None:
            sock.close()

    if ip and not ip.startswith("127."):
        return ip
    return None


def _parse_request(payload: bytes) -> tuple[str, str, bool]:
    """Parse the JSON payload sent by the central device."""

    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"无效的 JSON: {exc}") from exc

    ssid = data.get("ssid", "")
    password = data.get("password", "")
    hidden = bool(data.get("hidden", False))

    if not isinstance(ssid, str) or not isinstance(password, str):
        raise ValueError("ssid 和 password 必须是字符串")

    return ssid, password, hidden


class WiFiConfigService(Service):
    def __init__(self) -> None:
        super().__init__(SERVICE_UUID)
        self._last_response: bytes = json.dumps(
            {"success": False, "message": "尚未配置"}, ensure_ascii=False
        ).encode()

    @characteristic(
        CHARACTERISTIC_UUID,
        CharacteristicFlags.READ
        | CharacteristicFlags.WRITE
        | CharacteristicFlags.WRITE_WITHOUT_RESPONSE
        | CharacteristicFlags.NOTIFY,
    )
    def wifi_config(self, _options) -> bytes:
        """Allow centrals to read the latest status."""

        return self._last_response

    @wifi_config.setter
    def wifi_config(self, value: bytes, options: CharacteristicWriteOptions) -> None:
        loop = asyncio.get_event_loop()
        loop.create_task(self._process_request(bytes(value)))

    async def _process_request(self, payload: bytes) -> None:
        try:
            ssid, password, hidden = _parse_request(payload)
            result = await asyncio.to_thread(_connect_wifi, ssid, password, hidden)
        except Exception as exc:  # noqa: BLE001 - surface to client
            result = WiFiResult(False, f"处理失败: {exc}")

        self._last_response = result.to_payload()
        self.wifi_config.changed(self._last_response)


async def ensure_adapter_ready(adapter: Adapter) -> None:
    """Power on the adapter and enable discoverability/pairability."""

    if not await adapter.get_powered():
        await adapter.set_powered(True)

    iface = adapter._adapter_interface  # type: ignore[attr-defined]
    await iface.set_alias(DEVICE_NAME)
    await iface.set_discoverable(True)
    await iface.set_pairable(True)


async def advertise(service: WiFiConfigService) -> None:
    bus = await get_message_bus()

    if not await is_bluez_available(bus):
        raise RuntimeError("BlueZ 服务未运行，无法开启 BLE 广播")

    adapter = await Adapter.get_first(bus)
    await ensure_adapter_ready(adapter)

    agent = NoIoAgent()
    await agent.register(bus, default=True)

    await service.register(bus, adapter=adapter)

    advert = Advertisement(
        localName=DEVICE_NAME,
        serviceUUIDs=[SERVICE_UUID],
        appearance=0,
        timeout=0,
        discoverable=True,
        packet_type=PacketType.PERIPHERAL,
        includes=AdvertisingIncludes.LOCAL_NAME | AdvertisingIncludes.TX_POWER,
    )

    await advert.register(bus, adapter=adapter, path=ADVERT_PATH)

    print(f"✅ 正在广播 BLE 设备：{DEVICE_NAME}")
    print("📡 请在手机或其他终端中搜索该设备并写入 Wi-Fi 配置信息")

    # Keep the event loop alive until a termination signal is received.
    stop_event = asyncio.Event()

    def handle_stop() -> None:
        if not stop_event.is_set():
            stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_stop)
        except NotImplementedError:
            # add_signal_handler isn't available on some platforms (eg. Windows)
            signal.signal(sig, lambda _signum, _frame: handle_stop())

    try:
        await stop_event.wait()
    finally:
        print("🛑 停止广播，清理资源…")
        await service.unregister()
        await agent.unregister(bus)


async def main() -> None:
    service = WiFiConfigService()
    await advertise(service)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("🛑 程序已手动终止")
