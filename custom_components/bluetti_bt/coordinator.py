"""Coordinator for Bluetti integration."""

from __future__ import annotations
import asyncio
from datetime import timedelta
import logging
from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from bluetti_bt_lib import build_device, DeviceReader, DeviceReaderConfig
from bluetti_bt_lib.bluetooth.encryption import Message, MessageType
from bluetti_bt_lib.const import WRITE_UUID

from .utils import mac_loggable
from .types import FullDeviceConfig


class SafeDeviceReader(DeviceReader):
    """Device reader that ignores malformed encrypted notifications."""

    async def _notification_handler(self, _: int, data: bytearray):
        """Handle bt data."""
        self.logger.debug("Got new data")

        if self.config.use_encryption is True:
            message = Message(data)

            if message.is_pre_key_exchange:
                message.verify_checksum()

                if message.type == MessageType.CHALLENGE:
                    challenge_response = self.encryption.msg_challenge(message)
                    await self.client.write_gatt_char(WRITE_UUID, challenge_response)
                    return

                if message.type == MessageType.CHALLENGE_ACCEPTED:
                    self.logger.debug("Challenge accepted")
                    return

            if self.encryption.unsecure_aes_key is None:
                self.logger.warning(
                    "Received encrypted message before key initialization"
                )
                return

            key, iv = self.encryption.getKeyIv()
            try:
                decrypted = Message(self.encryption.aes_decrypt(message.buffer, key, iv))
            except ValueError as err:
                self.logger.debug("Ignoring invalid encrypted notification: %s", err)
                return

            if decrypted.is_pre_key_exchange:
                decrypted.verify_checksum()

                if decrypted.type == MessageType.PEER_PUBKEY:
                    peer_pubkey_response = self.encryption.msg_peer_pubkey(decrypted)
                    await self.client.write_gatt_char(WRITE_UUID, peer_pubkey_response)
                    return

                if decrypted.type == MessageType.PUBKEY_ACCEPTED:
                    self.encryption.msg_key_accepted(decrypted)
                    return

            data = decrypted.buffer

        self.notify_response.extend(data)

        if self.notify_future is None:
            return

        if self.notify_future.done():
            return

        self.notify_future.set_result(self.notify_response)


class PollingCoordinator(DataUpdateCoordinator):
    """Polling coordinator."""

    def __init__(
        self,
        hass: HomeAssistant,
        config: FullDeviceConfig,
        lock: asyncio.Lock,
    ):
        """Initialize coordinator."""
        super().__init__(
            hass,
            logging.getLogger(
                f"{__name__}.{mac_loggable(config.address).replace(':', '_')}"
            ),
            name="Bluetti polling coordinator",
            update_interval=timedelta(seconds=config.polling_interval),
        )

        self.config = config

        # Create client
        self.logger.info("Creating client for %s", config.name)
        bluetti_device = build_device(config.name)

        if bluetti_device is None:
            self.logger.error("Device is unknown type")
            self.async_shutdown()
            return None

        self.reader = SafeDeviceReader(
            config.address,
            bluetti_device,
            self.hass.loop.create_future,
            DeviceReaderConfig(
                config.polling_timeout,
                config.use_encryption,
            ),
            lock,
        )

    async def _async_update_data(self):
        """Fetch data from API endpoint.

        This is the place to pre-process the data to lookup tables
        so entities can quickly look up their data.
        """

        # Check if device is connected
        if (
            bluetooth.async_address_present(
                self.hass, self.config.address, connectable=True
            )
            is False
        ):
            self.logger.warning("Device not connected")
            self.last_update_success = False
            return None

        return await self.reader.read()
