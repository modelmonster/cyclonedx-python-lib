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

* :data:`AibomEncoding.NATIVE` emits prototype CycloneDX 1.8 AIBOM fields
  (``dataFlows[]``, ``trustZones[]``, component ``trustZone``,
  ``serviceData.bom-ref``) plus AIBOM Core self-description properties.
* :data:`AibomEncoding.PROPERTIES` emits a CycloneDX 1.7-valid BOM that carries
  AIBOM Core information as BOM-level properties.

The helpers never mutate the caller's :class:`Bom`. Returned BOMs are shallow
structural copies: top-level collections are rebuilt, contained model objects
are shared.
"""

from collections.abc import Iterable
from copy import copy
from typing import Optional
from warnings import warn

from .._internal.aibom_properties import (
    dataflow_property_name,
    inline_data_property_name,
    is_generated_aibom_property_name,
    node_property_name,
    service_data_property_name,
    trust_zone_property_name,
)
from ..model import DataClassification, Property
from ..model.aibom import (
    AIBOM_PROP_ENCODING,
    AIBOM_PROP_SPEC_VERSION,
    AIBOM_SPEC_VERSION_DEFAULT,
    AibomEncoding,
    AibomGraphSelfDescription,
    DataFlowEdge,
    TrustZone,
)
from ..model.bom import Bom
from ..model.component import Component
from ..model.service import Service
from ..schema import OutputFormat, SchemaVersion
from ..validation.aibom import AibomSemanticValidator, AibomSeverity
from . import BaseOutput
from .json import BY_SCHEMA_VERSION as _JSON_BY_SCHEMA_VERSION
from .xml import BY_SCHEMA_VERSION as _XML_BY_SCHEMA_VERSION


def _raise_on_semantic_errors(bom: Bom) -> None:
    errors = [
        finding for finding in AibomSemanticValidator.validate_bom(bom, check_discovery_properties=False)
        if finding.severity == AibomSeverity.ERROR
    ]
    if errors:
        messages = '; '.join(finding.message for finding in errors)
        raise ValueError(f'AIBOM semantic validation failed: {messages}')


def _strip_generated_aibom_properties(props: list[Property]) -> list[Property]:
    return [p for p in props if not is_generated_aibom_property_name(p.name)]


def _resolve_self_description(
    bom: Bom,
    self_description: Optional[AibomGraphSelfDescription],
) -> AibomGraphSelfDescription:
    if self_description is not None:
        return self_description
    try:
        return AibomGraphSelfDescription.from_properties(bom.properties)
    except (KeyError, ValueError) as error:
        raise ValueError(
            'AIBOM output requires Graph Self-Description properties or an explicit self_description'
        ) from error


def _copy_bom_with_properties(bom: Bom, properties: list[Property]) -> Bom:
    copied = copy(bom)
    copied.components = list(bom.components)
    copied.services = list(bom.services)
    copied.external_references = list(bom.external_references)
    copied.vulnerabilities = list(bom.vulnerabilities)
    copied.dependencies = list(bom.dependencies)
    copied.trust_zones = list(bom.trust_zones)
    copied.data_flows = list(bom.data_flows)
    copied.properties = properties
    return copied


def _edge_properties(edge: DataFlowEdge) -> list[Property]:
    edge_ref = edge.bom_ref.value
    assert edge_ref is not None
    if edge.properties:
        warn(
            'DataFlowEdge.properties cannot be represented in AIBOM properties compatibility mode; '
            f'dropping properties on dataflow {edge_ref!r}.',
            category=UserWarning,
            stacklevel=2,
        )
    out: list[Property] = [
        Property(name=dataflow_property_name(edge_ref, 'source'), value=edge.source.value),
        Property(name=dataflow_property_name(edge_ref, 'target'), value=edge.target.value),
    ]
    for op in edge.operations:
        out.append(Property(name=dataflow_property_name(edge_ref, 'operation'), value=op.value))
    for data_ref in edge.data_refs:
        out.append(Property(name=dataflow_property_name(edge_ref, 'dataRef'), value=data_ref.value))
    for data in edge.data:
        out.extend(_inline_data_properties(edge_ref, data))
    if edge.name:
        out.append(Property(name=dataflow_property_name(edge_ref, 'name'), value=edge.name))
    if edge.description:
        out.append(Property(name=dataflow_property_name(edge_ref, 'description'), value=edge.description))
    return out


def _inline_data_properties(edge_ref: str, data: DataClassification) -> list[Property]:
    if data.bom_ref is None or data.bom_ref.value is None:
        raise ValueError(
            f'AIBOM properties output requires inline data descriptors on dataflow {edge_ref!r} to have bom_ref'
        )
    data_ref = data.bom_ref.value
    return [
        Property(name=inline_data_property_name(edge_ref, data_ref, 'classification'), value=data.classification),
        Property(name=inline_data_property_name(edge_ref, data_ref, 'flow'), value=data.flow.value),
    ]


def _trust_zone_properties(tz: TrustZone) -> list[Property]:
    out: list[Property] = []
    if tz.description:
        out.append(Property(name=trust_zone_property_name(tz.name), value=tz.description))
    if tz.default:
        out.append(Property(name=trust_zone_property_name(tz.name, 'default'), value='true'))
    return out


def _component_trust_zone_properties(bom: Bom) -> list[Property]:
    out: list[Property] = []
    for c in _walk_components(bom, _referenced_node_refs(bom)):
        tz = getattr(c, 'trust_zone', None)
        if tz and c.bom_ref.value is not None:
            out.append(Property(name=node_property_name(c.bom_ref.value, 'trustZone'), value=tz))
    return out


def _service_data_descriptor_properties(bom: Bom) -> list[Property]:
    """
    Encode endpoint service-data descriptors used as ``dataRefs`` targets.

    CycloneDX 1.7 ``serviceData`` has no ``bom-ref`` of its own, so an AIBOM
    encoded as 1.7 properties must record the descriptor's owner, classification,
    and flow as BOM-level properties.
    """
    referenced_refs = {
        ref.value for edge in bom.data_flows for ref in edge.data_refs
        if ref.value is not None
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
            out.append(Property(name=service_data_property_name(ref.value, 'owner'), value=s.bom_ref.value))
            out.append(Property(name=service_data_property_name(ref.value, 'ownerType'), value='service'))
            out.append(Property(
                name=service_data_property_name(ref.value, 'classification'),
                value=str(d.classification),
            ))
            out.append(Property(name=service_data_property_name(ref.value, 'flow'), value=d.flow.value))
    return out


def _referenced_node_refs(bom: Bom) -> set[str]:
    refs: set[str] = set()
    for edge in bom.data_flows:
        if edge.source.value is not None:
            refs.add(edge.source.value)
        if edge.target.value is not None:
            refs.add(edge.target.value)
    return refs


def _walk_components(bom: Bom, referenced_node_refs: set[str]) -> list[Component]:
    out: list[Component] = []

    def _recurse(comps: Iterable[Component], include_all: bool) -> None:
        for c in comps:
            if include_all or c.bom_ref.value in referenced_node_refs:
                out.append(c)
            _recurse(c.components, include_all)

    _recurse(bom.components, True)
    if bom.metadata.component is not None:
        _recurse((bom.metadata.component,), False)
    return out


def _walk_services(bom: Bom) -> list[Service]:
    out: list[Service] = []

    def _recurse(svcs: Iterable[Service]) -> None:
        for s in svcs:
            out.append(s)
            _recurse(s.services)

    _recurse(bom.services)
    return out


def _base_aibom_properties(
    bom: Bom,
    *,
    self_description: AibomGraphSelfDescription,
    encoding: AibomEncoding,
    spec_version: str,
) -> list[Property]:
    new_properties: list[Property] = _strip_generated_aibom_properties(list(bom.properties))
    new_properties.append(Property(name=AIBOM_PROP_SPEC_VERSION, value=spec_version))
    new_properties.append(Property(name=AIBOM_PROP_ENCODING, value=encoding.value))
    new_properties.extend(self_description.as_properties())
    return new_properties


def make_aibom_properties_bom(
    bom: Bom,
    *,
    self_description: Optional[AibomGraphSelfDescription] = None,
    spec_version: str = AIBOM_SPEC_VERSION_DEFAULT,
    validate_semantics: bool = True,
) -> Bom:
    """
    Return a new :class:`Bom` carrying AIBOM Core as CycloneDX 1.7-compatible
    BOM-level properties.

    The original ``bom`` is not mutated. AIBOM native fields (``dataFlows[]``,
    ``trustZones[]``) are dropped from the returned BOM because CycloneDX 1.7
    has no schema slot for them.

    Raises:
        ValueError: when ``bom`` has no ``dataFlows[]``, has no Graph
            Self-Description, has inline edge data without ``bom_ref``, or
            semantic validation reports errors.
    """
    if not bom.data_flows:
        raise ValueError('AIBOM output requires at least one data flow')
    resolved_self_description = _resolve_self_description(bom, self_description)
    new_properties = _base_aibom_properties(
        bom,
        self_description=resolved_self_description,
        encoding=AibomEncoding.PROPERTIES,
        spec_version=spec_version,
    )
    validation_bom = _copy_bom_with_properties(bom, new_properties)
    if validate_semantics:
        _raise_on_semantic_errors(validation_bom)
    for edge in bom.data_flows:
        new_properties.extend(_edge_properties(edge))
    new_properties.extend(_service_data_descriptor_properties(bom))
    for tz in bom.trust_zones:
        new_properties.extend(_trust_zone_properties(tz))
    new_properties.extend(_component_trust_zone_properties(bom))
    copied = _copy_bom_with_properties(bom, new_properties)
    copied.trust_zones = []
    copied.data_flows = []
    return copied


def make_aibom_native_bom(
    bom: Bom,
    *,
    self_description: Optional[AibomGraphSelfDescription] = None,
    spec_version: str = AIBOM_SPEC_VERSION_DEFAULT,
    validate_semantics: bool = True,
) -> Bom:
    """
    Return a copy of ``bom`` with AIBOM Core self-description properties added.

    Native AIBOM fields (``trust_zones``, ``data_flows``, component
    ``trustZone``, service-data ``bom-ref``) flow through unchanged because the
    prototype CycloneDX 1.8 schema carries them.

    Raises:
        ValueError: when ``bom`` has no ``dataFlows[]``, has no Graph
            Self-Description, or semantic validation reports errors.
    """
    if not bom.data_flows:
        raise ValueError('AIBOM output requires at least one data flow')
    resolved_self_description = _resolve_self_description(bom, self_description)
    new_properties = _base_aibom_properties(
        bom,
        self_description=resolved_self_description,
        encoding=AibomEncoding.NATIVE,
        spec_version=spec_version,
    )
    copied = _copy_bom_with_properties(bom, new_properties)
    if validate_semantics:
        _raise_on_semantic_errors(copied)
    return copied


def make_aibom_outputter(
    bom: Bom,
    output_format: OutputFormat,
    *,
    schema_version: SchemaVersion,
    encoding: AibomEncoding = AibomEncoding.NATIVE,
    self_description: Optional[AibomGraphSelfDescription] = None,
    spec_version: str = AIBOM_SPEC_VERSION_DEFAULT,
    validate_semantics: bool = True,
) -> BaseOutput:
    """
    Build a CycloneDX outputter for an AIBOM payload, delegating to the
    existing JSON/XML outputter for the requested schema version.

    Generic V1.8 outputters can serialize native AIBOM fields without AIBOM
    Core self-description properties and without AIBOM semantic validation. Use
    this helper when the output is intended to claim AIBOM conformance.

    :param encoding: ``AibomEncoding.NATIVE`` requires
        ``schema_version is SchemaVersion.V1_8``.
        ``AibomEncoding.PROPERTIES`` requires ``schema_version is SchemaVersion.V1_7``.
    :raises ValueError: when the ``encoding``/``schema_version`` pair is unsupported,
        the BOM has no dataflows, required self-description is missing, or
        semantic validation reports errors.
    """
    if encoding is AibomEncoding.NATIVE:
        if schema_version is not SchemaVersion.V1_8:
            raise ValueError(
                f'AIBOM native encoding requires SchemaVersion.V1_8, got {schema_version}'
            )
        prepared = make_aibom_native_bom(
            bom,
            self_description=self_description,
            spec_version=spec_version,
            validate_semantics=validate_semantics,
        )
    elif encoding is AibomEncoding.PROPERTIES:
        if schema_version is not SchemaVersion.V1_7:
            raise ValueError(
                f'AIBOM properties encoding requires SchemaVersion.V1_7, got {schema_version}'
            )
        prepared = make_aibom_properties_bom(
            bom,
            self_description=self_description,
            spec_version=spec_version,
            validate_semantics=validate_semantics,
        )
    else:
        raise ValueError(f'Unsupported AIBOM encoding: {encoding!r}')

    if output_format is OutputFormat.JSON:
        return _JSON_BY_SCHEMA_VERSION[schema_version](prepared)
    if output_format is OutputFormat.XML:
        return _XML_BY_SCHEMA_VERSION[schema_version](prepared)
    raise ValueError(f'Unsupported output format: {output_format!r}')
