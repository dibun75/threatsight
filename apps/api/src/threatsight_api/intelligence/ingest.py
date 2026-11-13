from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

from threatsight_api.domain.extraction import DocumentLocation, MediaKind, ParsedDocument

MAX_EXTRACTED_CHARS = 500_000
SUPPORTED_EXTENSIONS = {
    ".pdf": "pdf",
    ".docx": "docx",
    ".txt": "text",
    ".md": "markdown",
    ".markdown": "markdown",
}


class DocumentIngestError(ValueError):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sniff_media_kind(filename: str, data: bytes) -> tuple[MediaKind, str]:
    suffix = Path(filename).suffix.lower()
    kind = SUPPORTED_EXTENSIONS.get(suffix)
    if data.startswith(b"%PDF"):
        return "pdf", "application/pdf"
    if _is_docx(data):
        return "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    if kind in {"text", "markdown"}:
        if b"\x00" in data[:4096]:
            raise DocumentIngestError("Binary files are not accepted as text")
        content_type = "text/markdown" if kind == "markdown" else "text/plain"
        return kind, content_type  # type: ignore[return-value]
    if kind == "pdf":
        raise DocumentIngestError("File extension is PDF but content is not a PDF")
    if kind == "docx":
        raise DocumentIngestError("File extension is DOCX but content is not a Word document")
    raise DocumentIngestError("Unsupported document type. Use PDF, DOCX, Markdown, or plain text.")


def parse_document(data: bytes, filename: str) -> ParsedDocument:
    if not data:
        raise DocumentIngestError("Empty document")
    kind, content_type = sniff_media_kind(filename, data)
    if kind == "pdf":
        locations, warnings = _parse_pdf(data)
        page_count = len(locations)
    elif kind == "docx":
        locations, warnings = _parse_docx(data)
        page_count = None
    else:
        locations, warnings = _parse_text(data)
        page_count = None
    extracted = "\n\n".join(item.text for item in locations if item.text.strip())
    if len(extracted) > MAX_EXTRACTED_CHARS:
        extracted = extracted[:MAX_EXTRACTED_CHARS]
        warnings.append("Extracted text truncated to the configured maximum")
    return ParsedDocument(
        media_kind=kind,
        content_type=content_type,
        filename=Path(filename).name or "upload",
        content_hash=sha256_hex(data),
        byte_size=len(data),
        extracted_text=extracted,
        locations=[loc.model_dump() for loc in locations],
        page_count=page_count,
        parse_warnings=warnings,
    )


def _is_docx(data: bytes) -> bool:
    if not data.startswith(b"PK"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
    except zipfile.BadZipFile:
        return False
    return "word/document.xml" in names and "[Content_Types].xml" in names


def _parse_pdf(data: bytes) -> tuple[list[DocumentLocation], list[str]]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover
        raise DocumentIngestError("PDF support is unavailable") from exc
    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception as exc:
        raise DocumentIngestError("Malformed PDF") from exc
    if getattr(reader, "is_encrypted", False):
        raise DocumentIngestError("Encrypted PDFs are not accepted")
    locations: list[DocumentLocation] = []
    warnings: list[str] = []
    cursor = 0
    try:
        pages = list(reader.pages)
    except Exception as exc:
        raise DocumentIngestError("Malformed PDF") from exc
    if not pages:
        raise DocumentIngestError("Malformed PDF")
    for index, page in enumerate(pages, start=1):
        try:
            text = (page.extract_text() or "").strip()
        except Exception:
            text = ""
            warnings.append(f"Page {index} text could not be extracted")
        end = cursor + len(text)
        locations.append(
            DocumentLocation(page=index, section=f"Page {index}", text=text, start_char=cursor, end_char=end)
        )
        cursor = end + 2
    return locations, warnings


def _parse_docx(data: bytes) -> tuple[list[DocumentLocation], list[str]]:
    try:
        from docx import Document
        from docx.opc.exceptions import PackageNotFoundError
    except ImportError as exc:  # pragma: no cover
        raise DocumentIngestError("DOCX support is unavailable") from exc
    try:
        document = Document(io.BytesIO(data))
    except (PackageNotFoundError, ValueError, KeyError, OSError, zipfile.BadZipFile) as exc:
        raise DocumentIngestError("Malformed DOCX") from exc
    except Exception as exc:
        raise DocumentIngestError("Malformed DOCX") from exc
    locations: list[DocumentLocation] = []
    cursor = 0
    current_section = "Document"
    buffer: list[str] = []

    def flush() -> None:
        nonlocal cursor
        text = "\n".join(buffer).strip()
        if not text:
            buffer.clear()
            return
        end = cursor + len(text)
        locations.append(
            DocumentLocation(
                page=None,
                section=current_section[:300],
                text=text,
                start_char=cursor,
                end_char=end,
            )
        )
        cursor = end + 2
        buffer.clear()

    for paragraph in document.paragraphs:
        raw = (paragraph.text or "").strip()
        if not raw:
            continue
        style = (paragraph.style.name if paragraph.style is not None else "") or ""
        if style.startswith("Heading"):
            flush()
            current_section = raw
            continue
        buffer.append(raw)
    flush()
    if not locations:
        locations.append(DocumentLocation(page=None, section="Document", text="", start_char=0, end_char=0))
    return locations, []


def _parse_text(data: bytes) -> tuple[list[DocumentLocation], list[str]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    text = text.replace("\x00", "")
    locations: list[DocumentLocation] = []
    cursor = 0
    current_section = "Document"
    buffer: list[str] = []

    def flush() -> None:
        nonlocal cursor
        body = "\n".join(buffer).strip()
        if not body:
            buffer.clear()
            return
        end = cursor + len(body)
        locations.append(
            DocumentLocation(
                page=None,
                section=current_section[:300],
                text=body,
                start_char=cursor,
                end_char=end,
            )
        )
        cursor = end + 2
        buffer.clear()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("#"):
            flush()
            current_section = line.lstrip("#").strip() or current_section
            continue
        buffer.append(raw_line.rstrip())
    flush()
    if not locations:
        locations.append(DocumentLocation(page=None, section="Document", text=text.strip(), start_char=0, end_char=len(text.strip())))
    return locations, []
