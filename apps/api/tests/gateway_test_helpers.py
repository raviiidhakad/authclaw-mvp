import json

from app.models.audit import AuditLog


class FakeScalarResult:
    def __init__(self, first=None, all_items=None):
        self._first = first
        self._all_items = all_items if all_items is not None else ([] if first is None else [first])

    def first(self):
        return self._first

    def all(self):
        return self._all_items


class FakeResult:
    def __init__(self, first=None, all_items=None):
        self._first = first
        self._scalars = FakeScalarResult(first=first, all_items=all_items)

    def scalars(self):
        return self._scalars

    def fetchone(self):
        return self._first

    def scalar(self):
        return self._first


class FakeDb:
    def __init__(self, *results, allow_empty_execute=False, unexpected_message="Unexpected DB query in gateway test"):
        self.results = list(results)
        self.added = []
        self.allow_empty_execute = allow_empty_execute
        self.unexpected_message = unexpected_message

    async def execute(self, stmt, *_args, **_kwargs):
        if self.allow_empty_execute:
            params = getattr(stmt.compile(), "params", {})
            if {"id", "tenant_id", "previous_hash", "hash", "metadata"}.issubset(params):
                self.added.append(
                    AuditLog(
                        id=params["id"],
                        tenant_id=params["tenant_id"],
                        user_id=params.get("user_id"),
                        event_type=params.get("event_type"),
                        action=params.get("action"),
                        resource=params.get("resource"),
                        resource_id=params.get("resource_id"),
                        metadata_=params.get("metadata"),
                        ip_address=params.get("ip_address"),
                        user_agent=params.get("user_agent"),
                        created_at=params.get("created_at"),
                        previous_hash=params.get("previous_hash"),
                        hash=params.get("hash"),
                    )
                )
                return FakeResult()
        if not self.results:
            if self.allow_empty_execute:
                return FakeResult()
            raise AssertionError(self.unexpected_message)
        return self.results.pop(0)

    def add(self, item):
        self.added.append(item)

    async def commit(self):
        return None

    async def rollback(self):
        return None

    async def flush(self):
        return None


class FakeScanResult:
    def __init__(self, text, detected=True, needle="person@example.test"):
        start = text.find(needle)
        self.detections = []
        self.sanitized_text = text
        self.latency_ms = 1
        if detected and start >= 0:
            self.detections = [
                {"entity_type": "EMAIL_ADDRESS", "start": start, "end": start + len(needle), "score": 0.99}
            ]
            self.sanitized_text = text.replace(needle, "<EMAIL_ADDRESS>")

    @property
    def has_detections(self):
        return bool(self.detections)

    @property
    def entity_types(self):
        return [detection["entity_type"] for detection in self.detections]


class FakeHttpResponse:
    def __init__(self, status_code=200, body=None, text=None):
        self.status_code = status_code
        self._body = body or {}
        self._text = text

    def json(self):
        return self._body

    @property
    def text(self):
        return self._text if self._text is not None else json.dumps(self._body)


def fake_async_client_factory(response):
    class FakeAsyncClient:
        calls = []

        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, json, headers):
            self.__class__.calls.append({"url": url, "json": json, "headers": headers})
            return response

    return FakeAsyncClient
