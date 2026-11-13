"""Bounds for the Junos reference adapter. No socket calls live here."""

from __future__ import annotations

import re

from threatsight_api.connectors.microsoft.bounds import CollectionFailure

CONTRACT = "junos-rpc-v1"
DEFAULT_PORT = 830
MAX_XML_BYTES = 262_144
MAX_DEPTH = 16
MAX_NODES = 2_000
MAX_TEXT = 200
MAX_ROUTES = 8
MAX_CONNECT_ATTEMPTS = 3
CONNECT_TIMEOUT_SECONDS = 10
READ_TIMEOUT_SECONDS = 20
DNS_TIMEOUT_SECONDS = 2
SESSION_SECONDS = 60
NETCONF_SUBSYSTEM = "netconf"

DEVICE_ID = re.compile(r"^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$")
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
LOCATOR = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
INTERFACE = re.compile(
    r"^(?:(?:ge|xe|et|lt|gr)-[0-9]+/[0-9]+/[0-9]+|(?:fxp|em|lo|st|ae|irb|vlan)[0-9]{1,3})(?:\.[0-9]{1,5})?$"
)
LABEL = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
ACCEPTED_ALGORITHMS = frozenset({"ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512"})
METADATA_HOSTS = frozenset({"metadata.google.internal", "metadata.internal"})
HOST_INBOUND = frozenset({"ssh", "netconf", "ping", "https", "traceroute"})
MANAGEMENT_SERVICES = frozenset({"ssh", "netconf", "http", "https", "telnet", "ftp", "snmp"})
SECRET_TAGS = frozenset({
    "pre-shared-key", "ssh-private-key", "private-key", "encrypted-password",
    "plain-text-password", "community", "secret", "password", "certificate",
    "local-certificate", "ca-certificate", "shared-secret",
})
DROPPED_TAGS = frozenset({
    "description", "comment", "help", "message", "error-message", "error-info", "announcement",
})

__all__ = ["CollectionFailure"]
