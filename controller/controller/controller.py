"""ACA-Py Controller."""

import asyncio
from dataclasses import asdict, is_dataclass
import logging
from json import dumps
from typing import (
    Any,
    AsyncContextManager,
    Mapping,
    Optional,
    Protocol,
    Type,
    TypeVar,
    Union,
    cast,
    overload,
    runtime_checkable,
)
from weakref import finalize
from urllib.parse import urlsplit

from aiohttp import ClientResponse, ClientSession
from pydantic import BaseModel

from .events import Event, EventQueue, Queue


LOGGER = logging.getLogger(__name__)
T = TypeVar("T")


@runtime_checkable
class Serde(Protocol):
    """Object supporting serialization and deserialization methods."""

    def serialize(self) -> Mapping[str, Any]:
        """Serialize object."""
        ...

    @classmethod
    def deserialize(cls: Type[T], value: Mapping[str, Any]) -> T:
        """Deserialize value to object."""
        ...


class Dataclass(Protocol):
    """Empty protocol for dataclass type hinting."""


Serializable = Union[Mapping[str, Any], Serde, BaseModel, Dataclass, None]


def _serialize(value: Serializable):
    """Serialize value."""
    if value is None:
        return None
    if isinstance(value, Mapping):
        return value
    if isinstance(value, Serde):
        return value.serialize()
    if isinstance(value, BaseModel):
        return value.dict(by_alias=True, exclude_unset=True)
    if is_dataclass(value):
        return asdict(value)
    raise TypeError(f"Could not serialize value {value}")


@overload
def _deserialize(value: Mapping[str, Any]) -> Mapping[str, Any]:
    ...


@overload
def _deserialize(value: Mapping[str, Any], as_type: Type[T]) -> T:
    ...


@overload
def _deserialize(value: Mapping[str, Any], as_type: None) -> Mapping[str, Any]:
    ...


def _deserialize(
    value: Mapping[str, Any], as_type: Optional[Type[T]] = None
) -> Union[T, Mapping[str, Any]]:
    """Deserialize value."""
    if as_type is None:
        return value
    if issubclass(as_type, Mapping):
        return cast(T, value)
    if issubclass(as_type, BaseModel):
        return as_type.parse_obj(value)
    if issubclass(as_type, Serde):
        return as_type.deserialize(value)
    if is_dataclass(as_type):
        return as_type(**value)
    raise TypeError(f"Could not deserialize value into type {as_type.__name__}")


class ControllerError(Exception):
    """Raised on error in controller."""


class Controller:
    """ACA-Py Controller."""

    def __init__(
        self,
        base_url: str,
        label: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ):
        self.base_url = base_url
        self.label = label or "ACA-Py"
        self.headers = headers
        self._event_queue: Optional[Queue[Event]] = None

    @property
    def event_queue(self) -> Queue[Event]:
        """Return event queue."""
        if self._event_queue is None:
            raise ControllerError("Controller is not set up")
        return self._event_queue

    async def setup(self) -> "Controller":
        """Set up the controller."""
        event_queue_context = EventQueue(self.label, self.base_url)
        self._event_queue = await event_queue_context.__aenter__()

        # Close event queue when controller falls out of scope
        def _close_event_queue(context: AsyncContextManager):
            coro = context.__aexit__(None, None, None)
            try:
                asyncio.get_running_loop().create_task(coro)
            except RuntimeError:
                asyncio.run(coro)

        finalize(self, _close_event_queue, event_queue_context)

        # Get settings event
        settings = await self._event_queue.get(lambda event: event.topic == "settings")
        self.label = settings.payload["label"]

        return self

    async def _handle_response(
        self,
        resp: ClientResponse,
        data: Optional[bytes] = None,
        json: Optional[Mapping[str, Any]] = None,
    ) -> Mapping[str, Any]:
        if data or json:
            LOGGER.info(
                "Request to %s %s %s: %s",
                self.label,
                resp.method,
                resp.url.path + resp.url.query_string,
                data or dumps(json, sort_keys=True, indent=2),
            )
        else:
            LOGGER.info(
                "Request to %s %s %s",
                self.label,
                resp.method,
                resp.url.path + resp.url.query_string,
            )
        resp.request_info

        if resp.ok and resp.content_type == "application/json":
            body = await resp.json()
            response_out = dumps(body, indent=2, sort_keys=True)
            if response_out.count("\n") > 30:
                response_out = dumps(body, sort_keys=True)
            LOGGER.info("Response: %s", response_out)
            return body

        body = await resp.text()
        if resp.ok:
            raise ControllerError(
                "Unexpected content type f{resp.content_type}: {body}"
            )
        raise ControllerError(f"Request failed: {resp.url} {body}")

    @overload
    async def get(
        self,
        url: str,
        *,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Mapping[str, Any]:
        ...

    @overload
    async def get(
        self,
        url: str,
        *,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        as_type: None,
    ) -> Mapping[str, Any]:
        ...

    @overload
    async def get(
        self,
        url: str,
        *,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        as_type: Type[T],
    ) -> T:
        ...

    async def get(
        self,
        url: str,
        *,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        as_type: Optional[Type[T]] = None,
    ) -> Union[T, Mapping[str, Any]]:
        """HTTP Get."""
        async with ClientSession(base_url=self.base_url, headers=headers) as session:
            async with session.get(url, params=params) as resp:
                body = await self._handle_response(resp)
                return _deserialize(body, as_type)

    @overload
    async def post(
        self,
        url: str,
        *,
        data: Optional[bytes] = None,
        json: Optional[Serializable] = None,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Mapping[str, Any]:
        """HTTP Post and return json."""
        ...

    @overload
    async def post(
        self,
        url: str,
        *,
        data: Optional[bytes] = None,
        json: Optional[Serializable] = None,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        as_type: None,
    ) -> Mapping[str, Any]:
        """HTTP Post and return json."""
        ...

    @overload
    async def post(
        self,
        url: str,
        *,
        data: Optional[bytes] = None,
        json: Optional[Serializable] = None,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        as_type: Type[T],
    ) -> T:
        """HTTP Post and parse returned json as type T."""
        ...

    async def post(
        self,
        url: str,
        *,
        data: Optional[bytes] = None,
        json: Optional[Serializable] = None,
        params: Optional[Mapping[str, str]] = None,
        headers: Optional[Mapping[str, str]] = None,
        as_type: Optional[Type[T]] = None,
    ) -> Union[T, Mapping[str, Any]]:
        """HTTP POST."""
        async with ClientSession(base_url=self.base_url, headers=headers) as session:
            json_ = _serialize(json)
            async with session.post(url, data=data, json=json_, params=params) as resp:
                body = await self._handle_response(resp, data=data, json=json_)
                return _deserialize(body, as_type)