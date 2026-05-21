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
AIBOM semantic validation.

Checks AIBOM graph consistency that the JSON/XML schemas cannot fully express.
See AIBOM draft v1 section A11.
"""

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from .._internal.aibom_properties import DecodedAibomProperties, decode_core_properties
from ..model import DataClassification, DataFlow as ServiceDataFlow, Property
from ..model.aibom import (
    AIBOM_PROP_COMPLETENESS,
    AIBOM_PROP_GENERATION_METHOD,
    AIBOM_PROP_GRAPH_TYPE,
    AIBOM_PROP_MODEL_REF,
    AIBOM_PROP_SCOPE,
    AIBOM_PROP_SERVICE_ROLE,
    AIBOM_PROP_SYSTEM_RELATIONSHIP,
    AIBOM_PROP_TRUST_PERSPECTIVE,
    AIBOM_PROPERTY_PREFIX,
    AIBOM_SERVICE_ROLE_MODEL_SERVING,
    AibomCompleteness,
    AibomSystemRelationship,
    DataFlowEdge,
    DataFlowOperation,
)
from ..model.bom import Bom
from ..model.component import Component, ComponentType
from ..model.service import Service


class AibomSeverity(str, Enum):
    """Severity of an AIBOM semantic validation finding."""
    ERROR = 'error'
    WARNING = 'warning'
    INFO = 'info'


@dataclass(frozen=True)
class AibomFinding:
    """A single AIBOM semantic validation finding."""
    severity: AibomSeverity
    message: str
    subject: Optional[str] = None


class AibomSemanticValidator:
    """
    AIBOM semantic validator.

    Returns a list of :class:`AibomFinding` instances. Does not raise. Callers
    decide whether errors block output.
    """

    @classmethod
    def validate_bom(cls, bom: Bom, *, check_discovery_properties: bool = True) -> list[AibomFinding]:
        decoded = decode_core_properties(bom.properties)
        edges = tuple(bom.data_flows) + decoded.data_flows
        referenced_node_refs = cls._referenced_node_refs(edges)
        node_refs, node_refs_with_owners = cls._collect_node_refs(bom, referenced_node_refs)
        edge_refs = [e.bom_ref.value for e in edges if e.bom_ref.value is not None]
        data_descriptor_refs, descriptor_owners, descriptors = cls._collect_service_data_refs(bom)
        inline_descriptor_refs = cls._collect_inline_data_refs(edges)
        node_ref_set = set(node_refs)
        descriptor_ref_set = set(data_descriptor_refs)
        inline_descriptor_ref_set = set(inline_descriptor_refs)
        component_refs = cls._collect_component_refs(bom)

        findings: list[AibomFinding] = []
        findings.extend(cls._findings_from_decode(decoded))
        findings.extend(cls._check_duplicate_refs(
            node_refs,
            edge_refs,
            data_descriptor_refs + inline_descriptor_refs,
            decoded.duplicate_edge_ids,
        ))
        findings.extend(cls._check_graph_self_description(bom, edges, decoded))
        findings.extend(cls._check_edge_resolution(
            edges,
            node_ref_set,
            descriptor_ref_set,
            inline_descriptor_ref_set,
            set(component_refs),
            descriptor_owners,
            descriptors,
        ))
        findings.extend(cls._check_trust_zones(bom, node_refs_with_owners))
        findings.extend(cls._check_trust_perspective(bom, node_refs_with_owners))
        findings.extend(cls._check_system_relationships(bom, node_refs_with_owners))
        findings.extend(cls._check_hosted_model_services(node_refs_with_owners, component_refs))
        if check_discovery_properties:
            findings.extend(cls._check_optional_discovery_properties(bom))
        return findings

    @staticmethod
    def _findings_from_decode(decoded: DecodedAibomProperties) -> list[AibomFinding]:
        findings = [
            AibomFinding(AibomSeverity.ERROR, finding.message, finding.subject)
            for finding in decoded.findings
        ]
        findings.extend(
            AibomFinding(
                AibomSeverity.WARNING,
                f'dataflow {edge_ref!r} has duplicate operation properties; duplicates are ignored',
                edge_ref,
            )
            for edge_ref in decoded.duplicate_operations
        )
        return findings

    @classmethod
    def _check_duplicate_refs(
        cls,
        node_refs: list[str],
        edge_refs: list[str],
        data_descriptor_refs: list[str],
        decoded_duplicate_edge_ids: tuple[str, ...],
    ) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        all_refs = list(node_refs) + edge_refs + data_descriptor_refs
        for ref, count in Counter(all_refs).items():
            if count > 1:
                findings.append(AibomFinding(
                    severity=AibomSeverity.ERROR,
                    message=(
                        'duplicate bom-ref across graph nodes, dataflow edges, '
                        f'and data descriptors: {ref!r}'
                    ),
                    subject=ref,
                ))
        for ref in decoded_duplicate_edge_ids:
            findings.append(AibomFinding(
                severity=AibomSeverity.ERROR,
                message=f'duplicate decoded Core dataflow target id: {ref!r}',
                subject=ref,
            ))
        return findings

    @classmethod
    def _check_graph_self_description(
        cls,
        bom: Bom,
        edges: tuple[DataFlowEdge, ...],
        decoded: DecodedAibomProperties,
    ) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        axis_names = (
            AIBOM_PROP_GRAPH_TYPE,
            AIBOM_PROP_GENERATION_METHOD,
            AIBOM_PROP_SCOPE,
            AIBOM_PROP_COMPLETENESS,
        )
        props = {p.name: p.value for p in bom.properties}
        has_axes = any(name in props for name in axis_names)
        has_graph_content = bool(edges) or bool(decoded.data_flows)
        if not has_axes and not has_graph_content:
            return findings

        for name in axis_names:
            value = props.get(name)
            if value is None or not value.strip():
                findings.append(AibomFinding(
                    severity=AibomSeverity.ERROR,
                    message=f'missing required AIBOM Graph Self-Description property {name}',
                    subject=name,
                ))
        completeness = props.get(AIBOM_PROP_COMPLETENESS)
        if completeness:
            try:
                AibomCompleteness(completeness)
            except ValueError:
                findings.append(AibomFinding(
                    severity=AibomSeverity.ERROR,
                    message=f'invalid aibom:completeness value: {completeness!r}',
                    subject=AIBOM_PROP_COMPLETENESS,
                ))
        if has_axes and not edges:
            findings.append(AibomFinding(
                severity=AibomSeverity.ERROR,
                message='AIBOM Graph Self-Description requires at least one in-document dataflow edge',
            ))
        return findings

    @classmethod
    def _check_edge_resolution(
        cls,
        edges: tuple[DataFlowEdge, ...],
        node_ref_set: set[str],
        descriptor_ref_set: set[str],
        inline_descriptor_ref_set: set[str],
        component_ref_set: set[str],
        descriptor_owners: dict[str, Service],
        descriptors: dict[str, DataClassification],
    ) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        for edge in edges:
            edge_ref = edge.bom_ref.value
            assert edge_ref is not None
            findings.extend(cls._check_edge_operations(edge_ref, edge))
            if edge.source.value not in node_ref_set:
                findings.append(AibomFinding(
                    severity=AibomSeverity.ERROR,
                    message=(
                        f'dataflow {edge_ref!r} source does not resolve '
                        f'to a graph node: {edge.source.value!r}'
                    ),
                    subject=edge_ref,
                ))
            if edge.target.value not in node_ref_set:
                findings.append(AibomFinding(
                    severity=AibomSeverity.ERROR,
                    message=(
                        f'dataflow {edge_ref!r} target does not resolve '
                        f'to a graph node: {edge.target.value!r}'
                    ),
                    subject=edge_ref,
                ))
            for data_ref in edge.data_refs:
                ref = data_ref.value
                assert ref is not None
                if ref in inline_descriptor_ref_set and cls._edge_has_inline_data(edge, ref):
                    continue
                if ref not in descriptor_ref_set:
                    if ref in node_ref_set.union(component_ref_set):
                        findings.append(cls._data_ref_to_component_finding(edge_ref, ref))
                    else:
                        findings.append(AibomFinding(
                            severity=AibomSeverity.ERROR,
                            message=(
                                f'dataflow {edge_ref!r} dataRef does not '
                                f'resolve to a data descriptor: {ref!r}'
                            ),
                            subject=edge_ref,
                        ))
                    continue
                owner_ref = descriptor_owners[ref].bom_ref.value
                if owner_ref not in (edge.source.value, edge.target.value):
                    severity = AibomSeverity.WARNING if edge.data else AibomSeverity.ERROR
                    findings.append(cls._data_ref_owner_finding(edge_ref, ref, owner_ref, severity))
                else:
                    findings.extend(cls._check_flow_consistency(edge, ref, descriptor_owners, descriptors))
        return findings

    @staticmethod
    def _check_edge_operations(edge_ref: str, edge: DataFlowEdge) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        # Runtime guard for callers that mutate DataFlowEdge._operations or pass
        # invalid values through Python despite the typed public setter. The
        # typed model cannot distinguish an omitted operations field from an
        # explicitly empty one after construction.
        operations: tuple[object, ...] = tuple(edge.operations)
        for operation in operations:
            if not isinstance(operation, DataFlowOperation):
                findings.append(AibomFinding(
                    severity=AibomSeverity.ERROR,
                    message=f'dataflow {edge_ref!r} operation is not a valid AIBOM operation: {operation!r}',
                    subject=edge_ref,
                ))
        return findings

    @staticmethod
    def _data_ref_to_component_finding(edge_ref: str, data_ref: str) -> AibomFinding:
        return AibomFinding(
            severity=AibomSeverity.ERROR,
            message=(
                f'dataflow {edge_ref!r} dataRef resolves to a component bom-ref ({data_ref!r}). '
                'Use the component as `source` or `target`, reference service-data by bom-ref, '
                'or provide an inline edge data descriptor.'
            ),
            subject=edge_ref,
        )

    @staticmethod
    def _data_ref_owner_finding(
        edge_ref: str,
        data_ref: str,
        owner_ref: Optional[str],
        severity: AibomSeverity,
    ) -> AibomFinding:
        return AibomFinding(
            severity=severity,
            message=(
                f'dataflow {edge_ref!r} dataRef {data_ref!r} is owned by service {owner_ref!r}; '
                'dataRef service-data descriptors should be owned by the source or target service.'
            ),
            subject=edge_ref,
        )

    @classmethod
    def _check_trust_zones(cls, bom: Bom, node_refs_with_owners: dict[str, object]) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        default_zone_names = [tz.name for tz in bom.trust_zones if tz.default]
        if len(default_zone_names) > 1:
            findings.append(AibomFinding(
                severity=AibomSeverity.ERROR,
                message=f'multiple trust zones have default=True: {sorted(default_zone_names)}',
            ))

        if bom.trust_zones:
            defined_names = {tz.name for tz in bom.trust_zones}
            for ref, node in node_refs_with_owners.items():
                tz = getattr(node, 'trust_zone', None)
                if tz and tz not in defined_names:
                    findings.append(AibomFinding(
                        severity=AibomSeverity.WARNING,
                        message=f'node {ref!r} declares trustZone {tz!r} not in trustZones[]',
                        subject=ref,
                    ))
        return findings

    @classmethod
    def _check_trust_perspective(cls, bom: Bom, node_refs_with_owners: dict[str, object]) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        perspective = cls._bom_property_value(bom, AIBOM_PROP_TRUST_PERSPECTIVE)
        if perspective is not None and not perspective.strip():
            findings.append(AibomFinding(
                severity=AibomSeverity.ERROR,
                message='aibom:trustPerspective must be a non-empty string',
                subject=AIBOM_PROP_TRUST_PERSPECTIVE,
            ))
        if cls._uses_trust_zones(bom, node_refs_with_owners) and perspective is None:
            findings.append(AibomFinding(
                severity=AibomSeverity.WARNING,
                message='trust zones are used but aibom:trustPerspective is not declared',
                subject=AIBOM_PROP_TRUST_PERSPECTIVE,
            ))
        return findings

    @classmethod
    def _check_system_relationships(cls, bom: Bom, node_refs_with_owners: dict[str, object]) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        has_relationship = False
        for ref, node in node_refs_with_owners.items():
            value = cls._property_value(getattr(node, 'properties', ()), AIBOM_PROP_SYSTEM_RELATIONSHIP)
            if value is None:
                continue
            has_relationship = True
            try:
                AibomSystemRelationship(value)
            except ValueError:
                findings.append(AibomFinding(
                    severity=AibomSeverity.ERROR,
                    message=f'node {ref!r} has invalid aibom:systemRelationship value: {value!r}',
                    subject=ref,
                ))

        scope = cls._bom_property_value(bom, AIBOM_PROP_SCOPE)
        if scope == 'ai-system' and not has_relationship and cls._has_boundary_crossing_node(node_refs_with_owners):
            findings.append(AibomFinding(
                severity=AibomSeverity.WARNING,
                message='aibom:scope=ai-system graph has boundary-crossing nodes but no graph node declares '
                        'aibom:systemRelationship',
                subject=AIBOM_PROP_SYSTEM_RELATIONSHIP,
            ))
        return findings

    @classmethod
    def _check_hosted_model_services(
        cls,
        node_refs_with_owners: dict[str, object],
        component_refs: dict[str, Component],
    ) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        for ref, node in node_refs_with_owners.items():
            if not isinstance(node, Service):
                continue
            role = cls._property_value(node.properties, AIBOM_PROP_SERVICE_ROLE)
            if role != AIBOM_SERVICE_ROLE_MODEL_SERVING:
                continue
            model_ref = cls._property_value(node.properties, AIBOM_PROP_MODEL_REF)
            if model_ref is None or not model_ref.strip():
                findings.append(AibomFinding(
                    severity=AibomSeverity.ERROR,
                    message=f'model-serving service {ref!r} must declare aibom:modelRef',
                    subject=ref,
                ))
                continue
            model_component = component_refs.get(model_ref)
            if model_component is None:
                findings.append(AibomFinding(
                    severity=AibomSeverity.ERROR,
                    message=f'model-serving service {ref!r} aibom:modelRef does not resolve: {model_ref!r}',
                    subject=ref,
                ))
                continue
            if model_component.type is not ComponentType.MACHINE_LEARNING_MODEL:
                findings.append(AibomFinding(
                    severity=AibomSeverity.ERROR,
                    message=(
                        f'model-serving service {ref!r} aibom:modelRef {model_ref!r} must resolve '
                        'to a machine-learning-model component'
                    ),
                    subject=ref,
                ))
        return findings

    @staticmethod
    def _check_optional_discovery_properties(bom: Bom) -> list[AibomFinding]:
        if not any(p.name.startswith(AIBOM_PROPERTY_PREFIX) for p in bom.properties):
            return []
        return []

    @staticmethod
    def _referenced_node_refs(edges: tuple[DataFlowEdge, ...]) -> set[str]:
        refs: set[str] = set()
        for edge in edges:
            if edge.source.value is not None:
                refs.add(edge.source.value)
            if edge.target.value is not None:
                refs.add(edge.target.value)
        return refs

    @staticmethod
    def _collect_node_refs(
        bom: Bom,
        referenced_node_refs: set[str],
    ) -> tuple[list[str], dict[str, object]]:
        refs: list[str] = []
        owners: dict[str, object] = {}

        def _walk_component(c: Component, include_all: bool) -> None:
            ref = c.bom_ref.value
            if ref is not None and (include_all or ref in referenced_node_refs):
                refs.append(ref)
                owners[ref] = c
            for child in c.components:
                _walk_component(child, include_all)

        def _walk_service(s: Service) -> None:
            ref = s.bom_ref.value
            if ref is not None:
                refs.append(ref)
                owners[ref] = s
            for child in s.services:
                _walk_service(child)

        for c in bom.components:
            _walk_component(c, True)
        if bom.metadata.component is not None:
            _walk_component(bom.metadata.component, False)
        for s in bom.services:
            _walk_service(s)
        return refs, owners

    @staticmethod
    def _collect_component_refs(bom: Bom) -> dict[str, Component]:
        refs: dict[str, Component] = {}

        def _walk(c: Component) -> None:
            if c.bom_ref.value is not None:
                refs[c.bom_ref.value] = c
            for child in c.components:
                _walk(child)

        for c in bom.components:
            _walk(c)
        if bom.metadata.component is not None:
            _walk(bom.metadata.component)
        return refs

    @staticmethod
    def _collect_service_data_refs(
        bom: Bom,
    ) -> tuple[list[str], dict[str, Service], dict[str, DataClassification]]:
        refs: list[str] = []
        owners: dict[str, Service] = {}
        descriptors: dict[str, DataClassification] = {}

        def _walk(s: Service) -> None:
            for d in s.data:
                if d.bom_ref is not None and d.bom_ref.value is not None:
                    refs.append(d.bom_ref.value)
                    owners[d.bom_ref.value] = s
                    descriptors[d.bom_ref.value] = d
            for child in s.services:
                _walk(child)

        for s in bom.services:
            _walk(s)
        return refs, owners, descriptors

    @staticmethod
    def _collect_inline_data_refs(edges: tuple[DataFlowEdge, ...]) -> list[str]:
        refs: list[str] = []
        for edge in edges:
            for data in edge.data:
                if data.bom_ref is not None and data.bom_ref.value is not None:
                    refs.append(data.bom_ref.value)
        return refs

    @staticmethod
    def _edge_has_inline_data(edge: DataFlowEdge, ref: str) -> bool:
        return any(data.bom_ref is not None and data.bom_ref.value == ref for data in edge.data)

    @staticmethod
    def _check_flow_consistency(
        edge: DataFlowEdge,
        ref: str,
        descriptor_owners: dict[str, Service],
        descriptors: dict[str, DataClassification],
    ) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        owner_service = descriptor_owners[ref]
        owner_ref = owner_service.bom_ref.value
        source_ref = edge.source.value
        target_ref = edge.target.value
        descriptor = descriptors[ref]
        flow = descriptor.flow
        edge_ref = edge.bom_ref.value
        assert edge_ref is not None
        if owner_ref == source_ref and owner_ref == target_ref:
            return findings
        if owner_ref == source_ref:
            if flow not in (ServiceDataFlow.OUTBOUND, ServiceDataFlow.BI_DIRECTIONAL, ServiceDataFlow.UNKNOWN):
                findings.append(AibomFinding(
                    severity=AibomSeverity.WARNING,
                    message=(
                        f'dataflow {edge_ref!r} source is the descriptor owner; '
                        f'serviceData.flow should be `outbound` or `bi-directional`, got {flow.value!r}'
                    ),
                    subject=edge_ref,
                ))
        elif owner_ref == target_ref:
            if flow not in (ServiceDataFlow.INBOUND, ServiceDataFlow.BI_DIRECTIONAL, ServiceDataFlow.UNKNOWN):
                findings.append(AibomFinding(
                    severity=AibomSeverity.WARNING,
                    message=(
                        f'dataflow {edge_ref!r} target is the descriptor owner; '
                        f'serviceData.flow should be `inbound` or `bi-directional`, got {flow.value!r}'
                    ),
                    subject=edge_ref,
                ))
        return findings

    @staticmethod
    def _property_value(properties: Iterable[Property], name: str) -> Optional[str]:
        for prop in properties:
            if prop.name == name and prop.value is not None:
                return prop.value
        return None

    @classmethod
    def _bom_property_value(cls, bom: Bom, name: str) -> Optional[str]:
        return cls._property_value(bom.properties, name)

    @classmethod
    def _uses_trust_zones(cls, bom: Bom, node_refs_with_owners: dict[str, object]) -> bool:
        if bom.trust_zones:
            return True
        return any(getattr(node, 'trust_zone', None) for node in node_refs_with_owners.values())

    @classmethod
    def _has_boundary_crossing_node(cls, node_refs_with_owners: dict[str, object]) -> bool:
        for node in node_refs_with_owners.values():
            if isinstance(node, Service):
                if cls._property_value(node.properties, AIBOM_PROP_SERVICE_ROLE) == AIBOM_SERVICE_ROLE_MODEL_SERVING:
                    return True
                if node.x_trust_boundary:
                    return True
        return False
