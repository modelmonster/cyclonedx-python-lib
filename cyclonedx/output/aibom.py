# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


"""
AIBOM System Structure output helpers.

Provides two output modes over one internal :class:`cyclonedx.model.bom.Bom`:

* :data:`AibomEncoding.NATIVE` — emit native CycloneDX 1.8 AIBOM fields
  (``dataFlows[]``, ``trustZones[]``, component ``trustZone``,
  ``serviceData.bom-ref``) plus ``aibom:`` discovery properties.
* :data:`AibomEncoding.PROPERTIES` — emit a CycloneDX 1.7-valid BOM that
  carries AIBOM information as BOM-level properties, per
  ``docs/specs/aibom-system-structure-proposal.md`` Appendix B.

The helpers never mutate the caller's :class:`Bom`.
"""

from enum import Enum
from typing import Optional

from ..model import Property
from ..model.aibom import DataFlowEdge, TrustZone
from ..model.bom import Bom
from ..model.component import Component
from ..model.service import Service
from ..schema import OutputFormat, SchemaVersion
from . import BaseOutput
from .json import BY_SCHEMA_VERSION as _JSON_BY_SCHEMA_VERSION
from .xml import BY_SCHEMA_VERSION as _XML_BY_SCHEMA_VERSION

AIBOM_SPEC_VERSION_DEFAULT = '0.1-draft'
AIBOM_PROPERTY_PREFIX = 'aibom:'


class AibomEncoding(str, Enum):
    """Output encoding mode for AIBOM payloads."""
    NATIVE = 'native'
    PROPERTIES = 'properties'


class AibomProfile(str, Enum):
    """AIBOM conformance profile, per AIBOM System Structure specification, section 3.2."""
    CORE = 'core'
    CLASSIFIED = 'classified'
    ZONED = 'zoned'
    FULL = 'full'


def _has_zoned_fields(bom: Bom) -> bool:
    if any(True for _ in bom.trust_zones):
        return True
    for c in bom.components:
        if getattr(c, 'trust_zone', None):
            return True
    for s in bom.services:
        if getattr(s, 'trust_zone', None):
            return True
    return False


def _has_data_refs(bom: Bom) -> bool:
    return any(e.data_ref is not None for e in bom.data_flows)


def infer_profile(bom: Bom) -> Optional[AibomProfile]:
    """
    Infer the lowest AIBOM profile that covers the fields a BOM intentionally emits.

    Returns ``None`` when the BOM has no ``data_flows[]``; AIBOM profiles require
    at least a graph (see AIBOM System Structure specification, section 3.2).
    """
    if not any(True for _ in bom.data_flows):
        return None
    has_data_refs = _has_data_refs(bom)
    has_zoned = _has_zoned_fields(bom)
    if has_data_refs and has_zoned:
        return AibomProfile.FULL
    if has_data_refs:
        return AibomProfile.CLASSIFIED
    if has_zoned:
        return AibomProfile.ZONED
    return AibomProfile.CORE


def _strip_aibom_properties(props: list[Property]) -> list[Property]:
    return [p for p in props if not p.name.startswith(AIBOM_PROPERTY_PREFIX)]


def _edge_properties(edge: DataFlowEdge) -> list[Property]:
    prefix = f'{AIBOM_PROPERTY_PREFIX}dataFlow:{edge.bom_ref.value}'
    out: list[Property] = [
        Property(name=f'{prefix}:source', value=edge.source.value),
        Property(name=f'{prefix}:target', value=edge.target.value),
    ]
    for op in edge.operations:
        out.append(Property(name=f'{prefix}:operation', value=op.value))
    if edge.data_ref is not None:
        out.append(Property(name=f'{prefix}:dataRef', value=edge.data_ref.value))
    if edge.name:
        out.append(Property(name=f'{prefix}:name', value=edge.name))
    if edge.description:
        out.append(Property(name=f'{prefix}:description', value=edge.description))
    return out


def _trust_zone_properties(tz: TrustZone) -> list[Property]:
    prefix = f'{AIBOM_PROPERTY_PREFIX}trustZone:{tz.name}'
    out: list[Property] = []
    if tz.description:
        out.append(Property(name=prefix, value=tz.description))
    if tz.default:
        out.append(Property(name=f'{prefix}:default', value='true'))
    return out


def _component_trust_zone_properties(bom: Bom) -> list[Property]:
    out: list[Property] = []
    for c in _walk_components(bom):
        tz = getattr(c, 'trust_zone', None)
        if tz:
            out.append(Property(
                name=f'{AIBOM_PROPERTY_PREFIX}node:{c.bom_ref.value}:trustZone',
                value=tz,
            ))
    return out


def _service_data_descriptor_properties(bom: Bom) -> list[Property]:
    """
    Encode service-data descriptors used as ``dataRef`` targets.

    CycloneDX 1.7 ``serviceData`` has no ``bom-ref`` of its own, so an AIBOM
    encoded as 1.7 properties must record the descriptor's owner, classification,
    and flow as BOM-level properties.
    """
    referenced_refs = {
        e.data_ref.value for e in bom.data_flows if e.data_ref is not None
    }
    if not referenced_refs:
        return []
    out: list[Property] = []
    seen: set[str] = set()
    for s in _walk_services(bom):
        for d in s.data:
            ref = d.bom_ref
            if ref is None or ref.value is None:
                continue
            if ref.value not in referenced_refs or ref.value in seen:
                continue
            seen.add(ref.value)
            prefix = f'{AIBOM_PROPERTY_PREFIX}data:{ref.value}'
            out.append(Property(name=f'{prefix}:owner', value=s.bom_ref.value))
            out.append(Property(name=f'{prefix}:ownerType', value='service'))
            out.append(Property(name=f'{prefix}:classification', value=str(d.classification)))
            out.append(Property(name=f'{prefix}:flow', value=d.flow.value))
    return out


def _walk_components(bom: Bom) -> list[Component]:
    out: list[Component] = []

    def _recurse(comps: object) -> None:
        for c in comps:  # type: ignore[attr-defined]
            out.append(c)
            _recurse(c.components)

    _recurse(bom.components)
    if bom.metadata.component is not None:
        out.append(bom.metadata.component)
        _recurse(bom.metadata.component.components)
    return out


def _walk_services(bom: Bom) -> list[Service]:
    out: list[Service] = []

    def _recurse(svcs: object) -> None:
        for s in svcs:  # type: ignore[attr-defined]
            out.append(s)
            _recurse(s.services)

    _recurse(bom.services)
    return out


def make_aibom_properties_bom(
    bom: Bom,
    *,
    profile: Optional[AibomProfile] = None,
    spec_version: str = AIBOM_SPEC_VERSION_DEFAULT,
) -> Bom:
    """
    Return a new :class:`Bom` carrying the same component, service, dependency,
    metadata, and vulnerability state as ``bom``, plus BOM-level ``aibom:``
    properties encoding the AIBOM graph for CycloneDX 1.7 schema compatibility.

    The original ``bom`` is not mutated. AIBOM native fields (``dataFlows[]``,
    ``trustZones[]``) are dropped from the returned BOM because CycloneDX 1.7
    has no schema slot for them.
    """
    resolved_profile = profile or infer_profile(bom) or AibomProfile.CORE
    new_properties: list[Property] = _strip_aibom_properties(list(bom.properties))
    new_properties.append(Property(name=f'{AIBOM_PROPERTY_PREFIX}specVersion', value=spec_version))
    new_properties.append(Property(name=f'{AIBOM_PROPERTY_PREFIX}encoding', value=AibomEncoding.PROPERTIES.value))
    new_properties.append(Property(name=f'{AIBOM_PROPERTY_PREFIX}profile', value=resolved_profile.value))
    for edge in bom.data_flows:
        new_properties.extend(_edge_properties(edge))
    new_properties.extend(_service_data_descriptor_properties(bom))
    for tz in bom.trust_zones:
        new_properties.extend(_trust_zone_properties(tz))
    new_properties.extend(_component_trust_zone_properties(bom))
    return Bom(
        components=list(bom.components),
        services=list(bom.services),
        external_references=list(bom.external_references),
        serial_number=bom.serial_number,
        version=bom.version,
        metadata=bom.metadata,
        dependencies=list(bom.dependencies),
        vulnerabilities=list(bom.vulnerabilities),
        properties=new_properties,
        definitions=bom.definitions,
    )


def make_aibom_native_bom(
    bom: Bom,
    *,
    profile: Optional[AibomProfile] = None,
    spec_version: str = AIBOM_SPEC_VERSION_DEFAULT,
) -> Bom:
    """
    Return a copy of ``bom`` with AIBOM discovery properties
    (``aibom:specVersion``, ``aibom:encoding=native``, ``aibom:profile``)
    added to ``properties[]``.

    Native AIBOM fields (``trust_zones``, ``data_flows``, component
    ``trustZone``, service-data ``bom-ref``) flow through unchanged because the
    CycloneDX 1.8 schema carries them.
    """
    resolved_profile = profile or infer_profile(bom) or AibomProfile.CORE
    new_properties: list[Property] = _strip_aibom_properties(list(bom.properties))
    new_properties.append(Property(name=f'{AIBOM_PROPERTY_PREFIX}specVersion', value=spec_version))
    new_properties.append(Property(name=f'{AIBOM_PROPERTY_PREFIX}encoding', value=AibomEncoding.NATIVE.value))
    new_properties.append(Property(name=f'{AIBOM_PROPERTY_PREFIX}profile', value=resolved_profile.value))
    return Bom(
        components=list(bom.components),
        services=list(bom.services),
        external_references=list(bom.external_references),
        serial_number=bom.serial_number,
        version=bom.version,
        metadata=bom.metadata,
        dependencies=list(bom.dependencies),
        vulnerabilities=list(bom.vulnerabilities),
        properties=new_properties,
        definitions=bom.definitions,
        trust_zones=list(bom.trust_zones),
        data_flows=list(bom.data_flows),
    )


def make_aibom_outputter(
    bom: Bom,
    output_format: OutputFormat,
    *,
    schema_version: SchemaVersion,
    encoding: AibomEncoding = AibomEncoding.NATIVE,
    profile: Optional[AibomProfile] = None,
    spec_version: str = AIBOM_SPEC_VERSION_DEFAULT,
) -> BaseOutput:
    """
    Build a CycloneDX outputter for an AIBOM payload, delegating to the
    existing JSON/XML outputter for the requested schema version.

    :param encoding: ``AibomEncoding.NATIVE`` requires
        ``schema_version is SchemaVersion.V1_8``.
        ``AibomEncoding.PROPERTIES`` requires ``schema_version is SchemaVersion.V1_7``.
    :raises ValueError: when the ``encoding``/``schema_version`` pair is unsupported.
    """
    if encoding is AibomEncoding.NATIVE:
        if schema_version is not SchemaVersion.V1_8:
            raise ValueError(
                f'AIBOM native encoding requires SchemaVersion.V1_8, got {schema_version}'
            )
        prepared = make_aibom_native_bom(bom, profile=profile, spec_version=spec_version)
    elif encoding is AibomEncoding.PROPERTIES:
        if schema_version is not SchemaVersion.V1_7:
            raise ValueError(
                f'AIBOM properties encoding requires SchemaVersion.V1_7, got {schema_version}'
            )
        prepared = make_aibom_properties_bom(bom, profile=profile, spec_version=spec_version)
    else:
        raise ValueError(f'Unsupported AIBOM encoding: {encoding!r}')

    if output_format is OutputFormat.JSON:
        return _JSON_BY_SCHEMA_VERSION[schema_version](prepared)
    if output_format is OutputFormat.XML:
        return _XML_BY_SCHEMA_VERSION[schema_version](prepared)
    raise ValueError(f'Unsupported output format: {output_format!r}')
