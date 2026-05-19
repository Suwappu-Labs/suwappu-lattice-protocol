from collections.abc import Iterable as _Iterable
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar
from typing import Optional as _Optional
from typing import Union as _Union

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf.internal import containers as _containers

DESCRIPTOR: _descriptor.FileDescriptor

class StoreShardRequest(_message.Message):
    __slots__ = ("entity_id", "shard_index", "encrypted_data")
    ENTITY_ID_FIELD_NUMBER: _ClassVar[int]
    SHARD_INDEX_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_DATA_FIELD_NUMBER: _ClassVar[int]
    entity_id: str
    shard_index: int
    encrypted_data: bytes
    def __init__(
        self,
        entity_id: _Optional[str] = ...,
        shard_index: _Optional[int] = ...,
        encrypted_data: _Optional[bytes] = ...,
    ) -> None: ...

class StoreShardResponse(_message.Message):
    __slots__ = ("success", "error")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    success: bool
    error: str
    def __init__(self, success: bool = ..., error: _Optional[str] = ...) -> None: ...

class FetchShardRequest(_message.Message):
    __slots__ = ("entity_id", "shard_index")
    ENTITY_ID_FIELD_NUMBER: _ClassVar[int]
    SHARD_INDEX_FIELD_NUMBER: _ClassVar[int]
    entity_id: str
    shard_index: int
    def __init__(
        self, entity_id: _Optional[str] = ..., shard_index: _Optional[int] = ...
    ) -> None: ...

class FetchShardResponse(_message.Message):
    __slots__ = ("found", "encrypted_data")
    FOUND_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_DATA_FIELD_NUMBER: _ClassVar[int]
    found: bool
    encrypted_data: bytes
    def __init__(self, found: bool = ..., encrypted_data: _Optional[bytes] = ...) -> None: ...

class AuditChallengeRequest(_message.Message):
    __slots__ = ("entity_id", "shard_index", "nonce")
    ENTITY_ID_FIELD_NUMBER: _ClassVar[int]
    SHARD_INDEX_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    entity_id: str
    shard_index: int
    nonce: bytes
    def __init__(
        self,
        entity_id: _Optional[str] = ...,
        shard_index: _Optional[int] = ...,
        nonce: _Optional[bytes] = ...,
    ) -> None: ...

class AuditChallengeResponse(_message.Message):
    __slots__ = ("found", "proof_hash")
    FOUND_FIELD_NUMBER: _ClassVar[int]
    PROOF_HASH_FIELD_NUMBER: _ClassVar[int]
    found: bool
    proof_hash: str
    def __init__(self, found: bool = ..., proof_hash: _Optional[str] = ...) -> None: ...

class RemoveShardRequest(_message.Message):
    __slots__ = ("entity_id", "shard_index")
    ENTITY_ID_FIELD_NUMBER: _ClassVar[int]
    SHARD_INDEX_FIELD_NUMBER: _ClassVar[int]
    entity_id: str
    shard_index: int
    def __init__(
        self, entity_id: _Optional[str] = ..., shard_index: _Optional[int] = ...
    ) -> None: ...

class RemoveShardResponse(_message.Message):
    __slots__ = ("removed",)
    REMOVED_FIELD_NUMBER: _ClassVar[int]
    removed: bool
    def __init__(self, removed: bool = ...) -> None: ...

class NodeInfoRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class NodeInfoResponse(_message.Message):
    __slots__ = ("node_id", "region", "shard_count", "evicted", "reputation_score")
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    REGION_FIELD_NUMBER: _ClassVar[int]
    SHARD_COUNT_FIELD_NUMBER: _ClassVar[int]
    EVICTED_FIELD_NUMBER: _ClassVar[int]
    REPUTATION_SCORE_FIELD_NUMBER: _ClassVar[int]
    node_id: str
    region: str
    shard_count: int
    evicted: bool
    reputation_score: float
    def __init__(
        self,
        node_id: _Optional[str] = ...,
        region: _Optional[str] = ...,
        shard_count: _Optional[int] = ...,
        evicted: bool = ...,
        reputation_score: _Optional[float] = ...,
    ) -> None: ...

class FetchShardsBatchRequest(_message.Message):
    __slots__ = ("requests",)
    REQUESTS_FIELD_NUMBER: _ClassVar[int]
    requests: _containers.RepeatedCompositeFieldContainer[FetchShardRequest]
    def __init__(
        self, requests: _Optional[_Iterable[_Union[FetchShardRequest, _Mapping]]] = ...
    ) -> None: ...

class FetchShardsBatchResponse(_message.Message):
    __slots__ = ("responses",)
    RESPONSES_FIELD_NUMBER: _ClassVar[int]
    responses: _containers.RepeatedCompositeFieldContainer[FetchShardResponse]
    def __init__(
        self, responses: _Optional[_Iterable[_Union[FetchShardResponse, _Mapping]]] = ...
    ) -> None: ...

class StoreShardsStreamResponse(_message.Message):
    __slots__ = ("stored_count", "failed_count")
    STORED_COUNT_FIELD_NUMBER: _ClassVar[int]
    FAILED_COUNT_FIELD_NUMBER: _ClassVar[int]
    stored_count: int
    failed_count: int
    def __init__(
        self, stored_count: _Optional[int] = ..., failed_count: _Optional[int] = ...
    ) -> None: ...
