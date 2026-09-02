# Copyright 2026 HMS Networks
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CertificateProfile:
    key: str
    title: str
    description: str
    extended_key_usage: tuple[str, ...]
    key_usage: tuple[str, ...]
    default_days: int = 397
    leaf_key_type: str | None = None
    leaf_key_size_or_curve: str | None = None
    leaf_digest: str | None = None


PROFILES = {
    "flexedge_https": CertificateProfile(
        key="flexedge_https",
        title="FlexEdge HTTPS server",
        description="Identifies a FlexEdge system or Crimson runtime web server.",
        extended_key_usage=("serverAuth",),
        key_usage=("digitalSignature", "keyEncipherment"),
    ),
    "ram_https": CertificateProfile(
        key="ram_https",
        title="Red Lion RAM HTTPS Server",
        description="Compatible HTTPS identity package for Red Lion RAM-9931 devices.",
        extended_key_usage=("serverAuth",),
        key_usage=("digitalSignature", "keyEncipherment"),
        default_days=3510,
        leaf_key_type="RSA",
        leaf_key_size_or_curve="RSA 2048",
        leaf_digest="SHA-256",
    ),
    # The UI exposes only FlexEdge in the first milestone. These definitions
    # establish the extension point for the next protocol workflows.
    "mqtt_broker": CertificateProfile(
        key="mqtt_broker",
        title="MQTT broker",
        description="Identifies an MQTT broker to connecting clients.",
        extended_key_usage=("serverAuth",),
        key_usage=("digitalSignature", "keyEncipherment"),
    ),
    "mqtt_client": CertificateProfile(
        key="mqtt_client",
        title="MQTT client",
        description="Identifies a device or application to an MQTT broker.",
        extended_key_usage=("clientAuth",),
        key_usage=("digitalSignature",),
    ),
    "opcua_server": CertificateProfile(
        key="opcua_server",
        title="OPC UA server",
        description="Base X.509 identity profile for an OPC UA server.",
        extended_key_usage=("serverAuth", "clientAuth"),
        key_usage=("digitalSignature", "keyEncipherment"),
        default_days=825,
    ),
    "opcua_client": CertificateProfile(
        key="opcua_client",
        title="OPC UA client",
        description="Base X.509 identity profile for an OPC UA client application.",
        extended_key_usage=("clientAuth",),
        key_usage=("digitalSignature", "keyEncipherment"),
        default_days=825,
    ),
}