import asyncio
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

import grpc

from app.config.env import (
    XRAY_API_ADDRESS,
    XRAY_BINARY_PATH,
    XRAY_CONFIG_PATH,
    XRAY_XHTTP_PORT,
)
from app.utils.keygen import gen_uuid
from app.xray.config_builder import (
    BACKUP_XHTTP_INBOUND_TAG,
    PRIMARY_INBOUND_TAG,
    LocalXrayConfigBuilder,
)
from app.xray.proto import (
    build_add_vless_user_request,
    build_remove_inbound_request,
    build_remove_user_request,
)

logger = logging.getLogger(__name__)

ALTER_INBOUND_METHOD = "/xray.app.proxyman.command.HandlerService/AlterInbound"
REMOVE_INBOUND_METHOD = "/xray.app.proxyman.command.HandlerService/RemoveInbound"


class LocalXrayController:
    """Manages local xray-core config rendering, process lifecycle, and gRPC HandlerService."""

    def __init__(
        self,
        api_address: str = XRAY_API_ADDRESS,
        config_path: str = XRAY_CONFIG_PATH,
        binary_path: str = XRAY_BINARY_PATH,
    ):
        self.api_address = api_address
        self.config_path = Path(config_path)
        self.binary_path = binary_path

    def write_config(self, config: dict) -> Path:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self.config_path.parent), prefix=".xray-", suffix=".json"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            os.replace(tmp_path, self.config_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise
        return self.config_path

    def _grpc_alter_inbound(self, request_bytes: bytes) -> None:
        with grpc.insecure_channel(self.api_address) as channel:
            stub = channel.unary_unary(
                ALTER_INBOUND_METHOD,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            stub(request_bytes, timeout=5.0)

    def _grpc_remove_inbound(self, tag: str) -> None:
        req = build_remove_inbound_request(tag)
        with grpc.insecure_channel(self.api_address) as channel:
            stub = channel.unary_unary(
                REMOVE_INBOUND_METHOD,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            stub(req, timeout=5.0)

    def add_user_to_inbound(
        self, tag: str, username: str, key: str, flow: str = ""
    ) -> None:
        user_uuid = gen_uuid(key)
        email = f"{username}"
        req = build_add_vless_user_request(
            tag=tag, email=email, user_uuid=user_uuid, flow=flow
        )
        try:
            self._grpc_alter_inbound(req)
        except grpc.RpcError as exc:
            # Ignore "already exists" or offline daemon during pre-setup tests
            if exc.code() == grpc.StatusCode.UNKNOWN and "already exists" in (
                exc.details() or ""
            ):
                return
            logger.warning(
                "Xray AlterInbound add failed on %s for %s: %s",
                tag,
                username,
                exc,
            )

    def remove_user_from_inbound(self, tag: str, username: str) -> None:
        req = build_remove_user_request(tag=tag, email=username)
        try:
            self._grpc_alter_inbound(req)
        except grpc.RpcError as exc:
            if exc.code() == grpc.StatusCode.UNKNOWN and "not found" in (
                exc.details() or ""
            ):
                return
            logger.warning(
                "Xray AlterInbound remove failed on %s for %s: %s",
                tag,
                username,
                exc,
            )

    def sync_user(
        self,
        username: str,
        key: str,
        *,
        active: bool,
        xhttp_enabled: bool = False,
    ) -> None:
        if active:
            self.add_user_to_inbound(
                PRIMARY_INBOUND_TAG,
                username,
                key,
                flow="xtls-rprx-vision",
            )
            if xhttp_enabled:
                self.add_user_to_inbound(
                    BACKUP_XHTTP_INBOUND_TAG, username, key, flow=""
                )
        else:
            self.remove_user_from_inbound(PRIMARY_INBOUND_TAG, username)
            if xhttp_enabled:
                self.remove_user_from_inbound(
                    BACKUP_XHTTP_INBOUND_TAG, username
                )

    def sync_all_users(
        self,
        users: Iterable[tuple[str, str, bool]],
        *,
        xhttp_enabled: bool = False,
    ) -> None:
        for username, key, active in users:
            if username:
                self.sync_user(
                    username,
                    key,
                    active=active,
                    xhttp_enabled=xhttp_enabled,
                )

    def add_xhttp_inbound_live(
        self,
        xhttp_secret_path: str,
        active_users: list[tuple[str, str]],
        port: int = XRAY_XHTTP_PORT,
    ) -> bool:
        """Add local XHTTP inbound via xray api adi without restarting Xray."""
        clients = [
            {"id": gen_uuid(key), "email": username}
            for username, key in active_users
            if username
        ]
        inbound = LocalXrayConfigBuilder.build_xhttp_inbound(
            xhttp_secret_path=xhttp_secret_path,
            clients=clients,
            port=port,
        )
        payload = {"inbounds": [inbound]}
        fd, tmp_path = tempfile.mkstemp(prefix=".xhttp-in-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            if os.path.exists(self.binary_path):
                res = subprocess.run(
                    [
                        self.binary_path,
                        "api",
                        "adi",
                        f"--server={self.api_address}",
                        tmp_path,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                return res.returncode == 0
            return False
        except Exception as exc:
            logger.warning("Failed to add live XHTTP inbound: %s", exc)
            return False
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def remove_xhttp_inbound_live(self) -> bool:
        """Remove local XHTTP inbound via gRPC without restarting Xray."""
        try:
            self._grpc_remove_inbound(BACKUP_XHTTP_INBOUND_TAG)
            return True
        except grpc.RpcError as exc:
            logger.warning("Failed to remove live XHTTP inbound: %s", exc)
            return False

    def restart_xray(self) -> bool:
        """Restart xray-core via supervisord when core settings (Reality keys/IPv6) change."""
        try:
            res = subprocess.run(
                ["supervisorctl", "restart", "xray"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            return res.returncode == 0
        except FileNotFoundError:
            logger.info("supervisorctl not present; config written to disk")
            return False
        except Exception as exc:
            logger.warning("Failed to restart xray via supervisorctl: %s", exc)
            return False

    async def check_api_reachable(self) -> bool:
        host, port_str = self.api_address.rsplit(":", 1)
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port_str)), timeout=2.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False


xray_controller = LocalXrayController()
