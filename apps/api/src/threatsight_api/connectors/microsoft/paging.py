"""Short cursors. Vendor continuation tokens stay in connector memory."""

from __future__ import annotations

from threatsight_api.connectors.microsoft.bounds import CURSOR


class PageCursor:
    def __init__(self, steps: int) -> None:
        self.steps = steps
        self.expected: str | None = None
        self._token: dict[tuple[int, int], str] = {}

    def position(self, cursor: str | None) -> tuple[int, int] | None:
        if cursor is None:
            self.expected = "0.0"
            self._token.clear()
            return 0, 0
        if cursor != self.expected or CURSOR.fullmatch(cursor) is None:
            return None
        step, page = (int(part) for part in cursor.split("."))
        if step >= self.steps or page > 100 or (page and (step, page) not in self._token):
            return None
        return step, page

    def token(self, step: int, page: int) -> str | None:
        return self._token.get((step, page))

    def issue(self, step: int, page: int, continuation: str | None) -> str | None:
        if continuation:
            issued = f"{step}.{page + 1}"
            self._token[(step, page + 1)] = continuation
        elif step + 1 < self.steps:
            issued = f"{step + 1}.0"
        else:
            issued = None
        self.expected = issued
        return issued
