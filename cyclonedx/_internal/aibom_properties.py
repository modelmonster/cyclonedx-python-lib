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
Internal AIBOM Core property grammar helpers.

This module is deliberately narrow glue for the AIBOM prototype. It is not a
general CycloneDX property parser.
"""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote, unquote

from sortedcontainers import SortedSet

from ..model import DataClassification, DataFlow, Property
from ..model.aibom import (
    AIBOM_PROP_COMPLETENESS,
    AIBOM_PROP_ENCODING,
    AIBOM_PROP_GENERATION_METHOD,
    AIBOM_PROP_GRAPH_TYPE,
    AIBOM_PROP_SCOPE,
    AIBOM_PROP_SPEC_VERSION,
    AIBOM_PROPERTY_PREFIX,
    DataFlowEdge,
    DataFlowOperation,
)

_SAFE_COMPAT_ID_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-'
_GENERATED_EXACT_PROPERTY_NAMES = {
    AIBOM_PROP_SPEC_VERSION,
    AIBOM_PROP_ENCODING,
    AIBOM_PROP_GRAPH_TYPE,
    AIBOM_PROP_GENERATION_METHOD,
    AIBOM_PROP_SCOPE,
    AIBOM_PROP_COMPLETENESS,
    f'{AIBOM_PROPERTY_PREFIX}profile',
}
_GENERATED_PREFIXES = (
    f'{AIBOM_PROPERTY_PREFIX}dataFlow:',
    f'{AIBOM_PROPERTY_PREFIX}data:',
    f'{AIBOM_PROPERTY_PREFIX}trustZone:',
    f'{AIBOM_PROPERTY_PREFIX}node:',
)


@dataclass(frozen=True)
class AibomPropertyDecodeFinding:
    """A non-fatal issue found while decoding AIBOM Core properties."""
    message: str
    subject: Optional[str] = None


@dataclass(frozen=True)
class DecodedAibomProperties:
    """Decoded view of the AIBOM Core properties understood by this prototype."""
    data_flows: tuple[DataFlowEdge, ...] = ()
    service_data: tuple[DataClassification, ...] = ()
    duplicate_edge_ids: tuple[str, ...] = ()
    duplicate_operations: tuple[str, ...] = ()
    findings: tuple[AibomPropertyDecodeFinding, ...] = ()


@dataclass
class _EdgeParts:
    source: str | None = None
    target: str | None = None
    operations: list[DataFlowOperation] = field(default_factory=list)
    data_refs: list[str] = field(default_factory=list)
    inline_data: dict[str, dict[str, str]] = field(default_factory=lambda: defaultdict(dict))
    name: str | None = None
    description: str | None = None
    duplicate_operations: bool = False


def compat_id_from_ref(ref: str) -> str:
    """Return a property-safe AIBOM compatibility id for ``ref``."""
    return quote(ref, safe=_SAFE_COMPAT_ID_CHARS)


def ref_from_compat_id(compat_id: str) -> str:
    """Decode an AIBOM compatibility id."""
    return unquote(compat_id)


def decoded_dataflow_target_id(compat_id: str) -> str:
    """Return the canonical Core decoded dataflow target id."""
    return f'{AIBOM_PROPERTY_PREFIX}dataFlow:{compat_id}'


def aibom_property_name(*parts: str) -> str:
    """Build an AIBOM property name from already-decided grammar parts."""
    return AIBOM_PROPERTY_PREFIX + ':'.join(parts)


def is_generated_aibom_property_name(name: str) -> bool:
    """Return true for property names this prototype owns and can safely regenerate."""
    return name in _GENERATED_EXACT_PROPERTY_NAMES or name.startswith(_GENERATED_PREFIXES)


def dataflow_property_name(edge_ref: str, leaf: str) -> str:
    return aibom_property_name('dataFlow', compat_id_from_ref(edge_ref), leaf)


def inline_data_property_name(edge_ref: str, data_ref: str, leaf: str) -> str:
    return aibom_property_name(
        'dataFlow',
        compat_id_from_ref(edge_ref),
        'data',
        compat_id_from_ref(data_ref),
        leaf,
    )


def service_data_property_name(data_ref: str, leaf: str) -> str:
    return aibom_property_name('data', compat_id_from_ref(data_ref), leaf)


def trust_zone_property_name(trust_zone_name: str, leaf: Optional[str] = None) -> str:
    prefix = aibom_property_name('trustZone', compat_id_from_ref(trust_zone_name))
    return f'{prefix}:{leaf}' if leaf else prefix


def node_property_name(node_ref: str, leaf: str) -> str:
    return aibom_property_name('node', compat_id_from_ref(node_ref), leaf)


def _decode_dataflow_property(
    parts: list[str],
    value: str,
    edge_parts: dict[str, _EdgeParts],
    duplicate_edge_ids: set[str],
    findings: list[AibomPropertyDecodeFinding],
) -> None:
    compat_id = parts[2]
    edge = edge_parts.setdefault(compat_id, _EdgeParts())
    if len(parts) == 4:
        _decode_dataflow_leaf(compat_id, parts[3], value, edge, duplicate_edge_ids, findings)
    elif len(parts) == 6 and parts[3] == 'data':
        data_id = ref_from_compat_id(parts[4])
        leaf = parts[5]
        if leaf in ('classification', 'flow'):
            edge.inline_data[data_id][leaf] = value


def _decode_dataflow_leaf(
    compat_id: str,
    leaf: str,
    value: str,
    edge: _EdgeParts,
    duplicate_edge_ids: set[str],
    findings: list[AibomPropertyDecodeFinding],
) -> None:
    if leaf == 'source':
        if edge.source is not None and edge.source != value:
            duplicate_edge_ids.add(decoded_dataflow_target_id(compat_id))
        edge.source = value
    elif leaf == 'target':
        if edge.target is not None and edge.target != value:
            duplicate_edge_ids.add(decoded_dataflow_target_id(compat_id))
        edge.target = value
    elif leaf == 'operation':
        _decode_operation(compat_id, value, edge, findings)
    elif leaf == 'dataRef':
        edge.data_refs.append(value)
    elif leaf == 'name':
        edge.name = value
    elif leaf == 'description':
        edge.description = value


def _decode_operation(
    compat_id: str,
    value: str,
    edge: _EdgeParts,
    findings: list[AibomPropertyDecodeFinding],
) -> None:
    try:
        operation = DataFlowOperation(value)
    except ValueError:
        findings.append(AibomPropertyDecodeFinding(
            message=f'unknown dataFlow operation property value: {value!r}',
            subject=decoded_dataflow_target_id(compat_id),
        ))
    else:
        if operation in edge.operations:
            edge.duplicate_operations = True
        edge.operations.append(operation)


def _decode_service_data_property(
    parts: list[str],
    value: str,
    service_data_parts: dict[str, dict[str, str]],
) -> None:
    data_id = ref_from_compat_id(parts[2])
    leaf = parts[3]
    if leaf in ('classification', 'flow', 'owner', 'ownerType'):
        service_data_parts[data_id][leaf] = value


def _decode_property(
    prop: Property,
    edge_parts: dict[str, _EdgeParts],
    service_data_parts: dict[str, dict[str, str]],
    duplicate_edge_ids: set[str],
    findings: list[AibomPropertyDecodeFinding],
) -> None:
    value = prop.value
    if value is None:
        return
    name_parts = prop.name.split(':')
    if len(name_parts) < 3 or name_parts[0] != 'aibom':
        return
    if name_parts[1] == 'dataFlow':
        _decode_dataflow_property(name_parts, value, edge_parts, duplicate_edge_ids, findings)
    elif name_parts[1] == 'data' and len(name_parts) == 4:
        _decode_service_data_property(name_parts, value, service_data_parts)


def _build_inline_data(
    edge_id: str,
    parts: _EdgeParts,
    findings: list[AibomPropertyDecodeFinding],
) -> list[DataClassification]:
    inline_data: list[DataClassification] = []
    for data_id, data_parts in parts.inline_data.items():
        if 'classification' not in data_parts or 'flow' not in data_parts:
            findings.append(AibomPropertyDecodeFinding(
                message='inline data property group is missing classification or flow',
                subject=edge_id,
            ))
            continue
        try:
            flow = DataFlow(data_parts['flow'])
        except ValueError:
            findings.append(AibomPropertyDecodeFinding(
                message=f'inline data property group has invalid flow: {data_parts["flow"]!r}',
                subject=edge_id,
            ))
            continue
        inline_data.append(DataClassification(
            bom_ref=data_id,
            classification=data_parts['classification'],
            flow=flow,
        ))
    return inline_data


def _build_service_data(
    service_data_parts: dict[str, dict[str, str]],
    findings: list[AibomPropertyDecodeFinding],
) -> list[DataClassification]:
    service_data: list[DataClassification] = []
    for data_id, data_parts in service_data_parts.items():
        if 'classification' not in data_parts or 'flow' not in data_parts:
            continue
        try:
            flow = DataFlow(data_parts['flow'])
        except ValueError:
            findings.append(AibomPropertyDecodeFinding(
                message=f'service data property group has invalid flow: {data_parts["flow"]!r}',
                subject=data_id,
            ))
            continue
        service_data.append(DataClassification(
            bom_ref=data_id,
            classification=data_parts['classification'],
            flow=flow,
        ))
    return service_data


def decode_core_properties(properties: Iterable[Property]) -> DecodedAibomProperties:
    """
    Decode the AIBOM Core property vocabulary emitted by this implementation.

    Invalid or incomplete edge groups are reported as findings and skipped. The
    semantic validator owns severity decisions.
    """
    edge_parts: dict[str, _EdgeParts] = {}
    service_data_parts: dict[str, dict[str, str]] = defaultdict(dict)
    duplicate_edge_ids: set[str] = set()
    findings: list[AibomPropertyDecodeFinding] = []

    for prop in properties:
        _decode_property(prop, edge_parts, service_data_parts, duplicate_edge_ids, findings)

    decoded_edges: list[DataFlowEdge] = []
    duplicate_operations: list[str] = []
    for compat_id, edge in edge_parts.items():
        edge_id = decoded_dataflow_target_id(compat_id)
        if edge.source is None or edge.target is None:
            findings.append(AibomPropertyDecodeFinding(
                message='dataFlow property group is missing source or target',
                subject=edge_id,
            ))
            continue
        if edge.duplicate_operations:
            duplicate_operations.append(edge_id)
        inline_data = _build_inline_data(edge_id, edge, findings)
        decoded_edges.append(DataFlowEdge(
            bom_ref=edge_id,
            source=edge.source,
            target=edge.target,
            operations=edge.operations,
            data_refs=edge.data_refs,
            data=inline_data,
            name=edge.name,
            description=edge.description,
        ))

    service_data = _build_service_data(service_data_parts, findings)

    seen_edge_ids: set[str] = set()
    for decoded_edge in decoded_edges:
        edge_ref = decoded_edge.bom_ref.value
        assert edge_ref is not None
        if edge_ref in seen_edge_ids:
            duplicate_edge_ids.add(edge_ref)
        seen_edge_ids.add(edge_ref)
    return DecodedAibomProperties(
        data_flows=tuple(SortedSet(decoded_edges)),
        service_data=tuple(SortedSet(service_data)),
        duplicate_edge_ids=tuple(sorted(duplicate_edge_ids)),
        duplicate_operations=tuple(sorted(duplicate_operations)),
        findings=tuple(findings),
    )
