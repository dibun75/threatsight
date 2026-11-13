"""Bounded XML parsing. DTD, entities, and external references are rejected."""

from __future__ import annotations

from dataclasses import dataclass

from defusedxml import ElementTree

from threatsight_api.connectors.junos.bounds import (
    DROPPED_TAGS,
    MAX_DEPTH,
    MAX_NODES,
    MAX_TEXT,
    MAX_XML_BYTES,
    SECRET_TAGS,
    CollectionFailure,
)

_NETCONF_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
_JUNOS_PREFIX = "http://xml.juniper.net/junos/"
_JUNOS_NETCONF = "http://xml.juniper.net/netconf/junos/1.0"


@dataclass(frozen=True)
class ParsedDocument:
    root: ElementTree.Element
    secrets_stripped: bool


def local_name(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def namespace(tag: object) -> str:
    if isinstance(tag, str) and tag.startswith("{") and "}" in tag:
        return tag[1:].split("}", 1)[0]
    return ""


def _namespace_allowed(value: str) -> bool:
    return value == _NETCONF_NS or value == _JUNOS_NETCONF or value.startswith(_JUNOS_PREFIX)


def parse_document(payload: bytes) -> ParsedDocument:
    if not isinstance(payload, bytes | bytearray):
        raise CollectionFailure("malformed_xml")
    if len(payload) > MAX_XML_BYTES:
        raise CollectionFailure("response_too_large")
    lowered = payload.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered or b"xinclude" in lowered or b"<!element" in lowered:
        raise CollectionFailure("malformed_xml")
    try:
        root = ElementTree.fromstring(payload)
    except Exception:
        raise CollectionFailure("malformed_xml") from None
    stripped = False
    count = 0

    def walk(node: ElementTree.Element, depth: int) -> None:
        nonlocal count, stripped
        if depth > MAX_DEPTH:
            raise CollectionFailure("xml_depth_exceeded")
        count += 1
        if count > MAX_NODES:
            raise CollectionFailure("xml_node_limit")
        if not isinstance(node.tag, str) or not _namespace_allowed(namespace(node.tag)):
            raise CollectionFailure("malicious_namespace")
        name = local_name(node.tag)
        for key, value in list(node.attrib.items()):
            if not isinstance(value, str) or len(value) > MAX_TEXT or any(ord(char) < 32 for char in value):
                raise CollectionFailure("malformed_xml")
            if namespace(key) and not _namespace_allowed(namespace(key)):
                raise CollectionFailure("malicious_namespace")
        if name in SECRET_TAGS or name in DROPPED_TAGS:
            if name in SECRET_TAGS:
                stripped = True
            node.text = None
            node.tail = None
            node[:] = []
            return
        if node.text is not None and len(node.text) > MAX_TEXT:
            raise CollectionFailure("response_too_large")
        for child in list(node):
            walk(child, depth + 1)

    walk(root, 1)
    if local_name(root.tag) not in {"hello", "rpc-reply"}:
        raise CollectionFailure("malformed_xml")
    return ParsedDocument(root, stripped)
