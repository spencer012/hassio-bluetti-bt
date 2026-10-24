"""Coordinator for Bluetti integration."""

from __future__ import annotations
import asyncio
from datetime import timedelta
import logging
from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from bluetti_bt_lib import build_device, DeviceReader, DeviceReaderConfig

from .utils import mac_loggable
from .types import FullDeviceConfig

# Entities go unavailable after this many failed polls in a row (see the
# _unavailable_counter in the entity platforms). Single failures are normal
# over BLE, so the coordinator only reports a failure once it lasts that long.
FAILED_POLLS_BEFORE_WARNING = 5


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

        self._failed_polls = 0

        self.reader = DeviceReader(
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
            self._poll_failed("Device not in range of a connectable Bluetooth adapter")
            self.last_update_success = False
            return None

        data = await self.reader.read()

        if data is None:
            self._poll_failed(getattr(self.reader, "last_error", None) or "No data")
        else:
            self._poll_succeeded()

        return data

    def _poll_failed(self, error: str):
        self._failed_polls += 1
        self.logger.debug("Poll %s failed: %s", self._failed_polls, error)

        if self._failed_polls == FAILED_POLLS_BEFORE_WARNING:
            self.logger.warning(
                "%s: %s failed polls in a row, entities are unavailable until "
                "a poll succeeds. Last error: %s",
                self.config.name,
                self._failed_polls,
                error,
            )

    def _poll_succeeded(self):
        if self._failed_polls >= FAILED_POLLS_BEFORE_WARNING:
            self.logger.info(
                "%s: polling recovered after %s failed polls",
                self.config.name,
                self._failed_polls,
            )
        self._failed_polls = 0
