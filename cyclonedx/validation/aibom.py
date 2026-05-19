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
See AIBOM System Structure specification, section 10.4.
"""

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..model import DataFlow as ServiceDataFlow
from ..model.aibom import AIBOM_PROPERTY_PREFIX, AibomProfile, DataFlowEdge, DataFlowOperation
from ..model.bom import Bom
from ..model.component import Component
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

    See AIBOM System Structure specification, section 10.4.
    """

    @classmethod
    def validate_bom(cls, bom: Bom, *, check_discovery_properties: bool = True) -> list[AibomFinding]:
        referenced_node_refs = cls._referenced_node_refs(bom)
        node_refs, node_refs_with_owners = cls._collect_node_refs(bom, referenced_node_refs)
        edge_refs = [e.bom_ref.value for e in bom.data_flows if e.bom_ref.value is not None]
        data_descriptor_refs, descriptor_owners = cls._collect_service_data_refs(bom)
        node_ref_set = set(node_refs)
        descriptor_ref_set = set(data_descriptor_refs)
        component_ref_set = cls._collect_component_refs(bom)

        findings: list[AibomFinding] = []
        findings.extend(cls._check_duplicate_refs(node_refs, edge_refs, data_descriptor_refs))
        findings.extend(cls._check_edge_resolution(
            bom, node_ref_set, descriptor_ref_set, component_ref_set, descriptor_owners,
        ))
        findings.extend(cls._check_trust_zones(bom, node_refs_with_owners))
        findings.extend(cls._check_profile(bom))
        if check_discovery_properties:
            findings.extend(cls._check_discovery_properties(bom))
        return findings

    @classmethod
    def _check_duplicate_refs(
        cls,
        node_refs: list[str],
        edge_refs: list[str],
        data_descriptor_refs: list[str],
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
        return findings

    @classmethod
    def _check_edge_resolution(
        cls,
        bom: Bom,
        node_ref_set: set[str],
        descriptor_ref_set: set[str],
        component_ref_set: set[str],
        descriptor_owners: dict[str, Service],
    ) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        for edge in bom.data_flows:
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
            if edge.data_ref is not None:
                ref = edge.data_ref.value
                assert ref is not None
                if ref not in descriptor_ref_set and ref in node_ref_set.union(component_ref_set):
                    findings.append(cls._data_ref_to_component_finding(edge_ref, ref))
                elif ref not in descriptor_ref_set:
                    findings.append(AibomFinding(
                        severity=AibomSeverity.ERROR,
                        message=(
                            f'dataflow {edge_ref!r} dataRef does not '
                            f'resolve to a data descriptor: {ref!r}'
                        ),
                        subject=edge_ref,
                    ))
                else:
                    findings.extend(cls._check_flow_consistency(edge, descriptor_owners))
        return findings

    @staticmethod
    def _check_edge_operations(edge_ref: str, edge: DataFlowEdge) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        # Runtime guard for callers that mutate DataFlowEdge._operations or pass
        # invalid values through Python despite the typed public setter.
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
                'Component data descriptors are out of scope in this implementation; use the '
                'component as `source` or `target` instead, or reference a `serviceData.bom-ref`.'
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
    def _check_profile(cls, bom: Bom) -> list[AibomFinding]:
        declared_profile = cls._declared_profile(bom)
        if declared_profile is not None and not bom.data_flows:
            return [AibomFinding(
                severity=AibomSeverity.ERROR,
                message=(
                    f'declared aibom:profile={declared_profile.value!r} requires `dataFlows[]` '
                    'with at least one edge'
                ),
            )]
        return []

    @classmethod
    def _check_discovery_properties(cls, bom: Bom) -> list[AibomFinding]:
        if not cls._has_aibom_content(bom):
            return []
        findings: list[AibomFinding] = []
        prop_names = {p.name for p in bom.properties}
        if f'{AIBOM_PROPERTY_PREFIX}specVersion' not in prop_names:
            findings.append(AibomFinding(
                severity=AibomSeverity.INFO,
                message='missing BOM property aibom:specVersion',
            ))
        if f'{AIBOM_PROPERTY_PREFIX}profile' not in prop_names:
            findings.append(AibomFinding(
                severity=AibomSeverity.INFO,
                message='missing BOM property aibom:profile',
            ))
        return findings

    @classmethod
    def _has_aibom_content(cls, bom: Bom) -> bool:
        if bom.data_flows or bom.trust_zones:
            return True
        if any(p.name.startswith(AIBOM_PROPERTY_PREFIX) for p in bom.properties):
            return True
        _, graph_node_owners = cls._collect_node_refs(bom, cls._referenced_node_refs(bom))
        if any(getattr(node, 'trust_zone', None) for node in graph_node_owners.values()):
            return True
        data_descriptor_refs, _ = cls._collect_service_data_refs(bom)
        return bool(data_descriptor_refs)

    @staticmethod
    def _referenced_node_refs(bom: Bom) -> set[str]:
        refs: set[str] = set()
        for edge in bom.data_flows:
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
            # metadata.component is only a graph node when an edge references it;
            # root components are always graph-node candidates.
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
    def _collect_component_refs(bom: Bom) -> set[str]:
        refs: set[str] = set()

        def _walk(c: Component) -> None:
            if c.bom_ref.value is not None:
                refs.add(c.bom_ref.value)
            for child in c.components:
                _walk(child)

        for c in bom.components:
            _walk(c)
        if bom.metadata.component is not None:
            _walk(bom.metadata.component)
        return refs

    @staticmethod
    def _collect_service_data_refs(bom: Bom) -> tuple[list[str], dict[str, Service]]:
        refs: list[str] = []
        owners: dict[str, Service] = {}

        def _walk(s: Service) -> None:
            for d in s.data:
                if d.bom_ref is not None and d.bom_ref.value is not None:
                    refs.append(d.bom_ref.value)
                    owners[d.bom_ref.value] = s
            for child in s.services:
                _walk(child)

        for s in bom.services:
            _walk(s)
        return refs, owners

    @staticmethod
    def _check_flow_consistency(
        edge: DataFlowEdge,
        descriptor_owners: dict[str, Service],
    ) -> list[AibomFinding]:
        findings: list[AibomFinding] = []
        assert edge.data_ref is not None
        ref = edge.data_ref.value
        assert ref is not None
        owner_service = descriptor_owners[ref]
        owner_ref = owner_service.bom_ref.value
        source_ref = edge.source.value
        target_ref = edge.target.value
        descriptor = next(
            (d for d in owner_service.data if d.bom_ref is not None and d.bom_ref.value == ref),
            None,
        )
        if descriptor is None or descriptor.flow is None:
            return findings
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
    def _declared_profile(bom: Bom) -> Optional[AibomProfile]:
        for p in bom.properties:
            if p.name == f'{AIBOM_PROPERTY_PREFIX}profile':
                try:
                    return AibomProfile(p.value)
                except ValueError:
                    return None
        return None
