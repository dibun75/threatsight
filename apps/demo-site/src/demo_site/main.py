from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse

from demo_site.pages import PAGES, ROBOTS_TXT

app = FastAPI(title="ThreatSight demo site", version="1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "threatsight-demo-site", "synthetic": True}


@app.get("/", response_class=HTMLResponse)
def home() -> HTMLResponse:
    return HTMLResponse(PAGES["/"])


@app.get("/robots.txt")
def robots() -> Response:
    return Response(content=ROBOTS_TXT, media_type="text/plain")


@app.get("/{path:path}", response_class=HTMLResponse)
def page(path: str) -> HTMLResponse:
    key = "/" if path in {"", "/"} else f"/{path.rstrip('/')}"
    html = PAGES.get(key)
    if html is None:
        return HTMLResponse("<p>Not found</p>", status_code=404)
    return HTMLResponse(html)
