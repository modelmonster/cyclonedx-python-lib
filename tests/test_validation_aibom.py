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

from unittest import TestCase

from cyclonedx.model import DataClassification, DataFlow as ServiceDataFlow, Property
from cyclonedx.model.aibom import DataFlowEdge, DataFlowOperation, TrustZone
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.service import Service
from cyclonedx.validation.aibom import AibomSemanticValidator, AibomSeverity


def _findings_with(bom: Bom) -> list[tuple[str, str]]:
    return [(f.severity.value, f.message) for f in AibomSemanticValidator.validate_bom(bom)]


class TestAibomSemanticValidator(TestCase):

    def test_valid_bom_has_no_errors(self) -> None:
        svc = Service(
            name='svc1', bom_ref='svc1',
            data=[DataClassification(flow=ServiceDataFlow.OUTBOUND, classification='PII', bom_ref='data-pii')],
        )
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1', trust_zone='internal-vpc')],
            services=[svc],
            trust_zones=[TrustZone(name='internal-vpc', default=True)],
            data_flows=[
                DataFlowEdge(
                    bom_ref='df-1', source='svc1', target='comp1',
                    operations=[DataFlowOperation.READ], data_ref='data-pii',
                ),
            ],
            properties=[
                Property(name='aibom:specVersion', value='0.1-draft'),
                Property(name='aibom:profile', value='full'),
            ],
        )
        findings = AibomSemanticValidator.validate_bom(bom)
        errors = [f for f in findings if f.severity == AibomSeverity.ERROR]
        self.assertEqual([], errors, findings)

    def test_unresolved_source_is_error(self) -> None:
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1')],
            services=[Service(name='svc1', bom_ref='svc1')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='ghost', target='svc1')],
        )
        msgs = [m for sev, m in _findings_with(bom) if sev == 'error' and 'source' in m]
        self.assertTrue(any('ghost' in m for m in msgs), msgs)

    def test_unresolved_target_is_error(self) -> None:
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='comp1', target='ghost')],
        )
        msgs = [m for sev, m in _findings_with(bom) if sev == 'error' and 'target' in m]
        self.assertTrue(any('ghost' in m for m in msgs), msgs)

    def test_unresolved_data_ref_is_error(self) -> None:
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1')],
            services=[Service(name='svc1', bom_ref='svc1')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='comp1', target='svc1', data_ref='unknown-data')],
        )
        msgs = [m for sev, m in _findings_with(bom) if sev == 'error' and 'dataRef' in m]
        self.assertTrue(any('unknown-data' in m for m in msgs), msgs)

    def test_data_ref_to_component_bom_ref_is_error(self) -> None:
        bom = Bom(
            components=[Component(name='comp-data', bom_ref='comp-data', type=__import__(
                'cyclonedx.model.component', fromlist=['ComponentType']
            ).ComponentType.DATA)],
            services=[Service(name='svc1', bom_ref='svc1')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='svc1', target='comp-data', data_ref='comp-data')],
        )
        msgs = [m for sev, m in _findings_with(bom) if sev == 'error' and 'dataRef' in m]
        self.assertTrue(any('graph node' in m for m in msgs), msgs)

    def test_duplicate_default_trust_zones_is_error(self) -> None:
        bom = Bom(
            components=[Component(name='c', bom_ref='c')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='c', target='c')],
            trust_zones=[TrustZone(name='a', default=True), TrustZone(name='b', default=True)],
        )
        msgs = [m for sev, m in _findings_with(bom) if sev == 'error' and 'default' in m]
        self.assertTrue(len(msgs) > 0, msgs)

    def test_undefined_trust_zone_is_warning(self) -> None:
        bom = Bom(
            components=[Component(name='c', bom_ref='c', trust_zone='ghost-zone')],
            services=[Service(name='svc', bom_ref='svc')],
            trust_zones=[TrustZone(name='internal-vpc')],
            data_flows=[DataFlowEdge(bom_ref='df', source='c', target='svc')],
        )
        msgs = [m for sev, m in _findings_with(bom) if sev == 'warning' and 'ghost-zone' in m]
        self.assertTrue(len(msgs) > 0, msgs)

    def test_profile_without_data_flows_is_error(self) -> None:
        bom = Bom(
            components=[Component(name='c', bom_ref='c')],
            properties=[Property(name='aibom:profile', value='core')],
        )
        msgs = [m for sev, m in _findings_with(bom) if sev == 'error' and 'profile' in m]
        self.assertTrue(len(msgs) > 0, msgs)

    def test_missing_spec_version_is_info(self) -> None:
        bom = Bom(
            components=[Component(name='c', bom_ref='c')],
            services=[Service(name='svc', bom_ref='svc')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='c', target='svc')],
        )
        msgs = [m for sev, m in _findings_with(bom) if sev == 'info' and 'aibom:specVersion' in m]
        self.assertTrue(len(msgs) > 0, msgs)

    def test_flow_mismatch_inbound_at_source_is_warning(self) -> None:
        svc = Service(
            name='svc1', bom_ref='svc1',
            data=[DataClassification(flow=ServiceDataFlow.INBOUND, classification='PII', bom_ref='data-pii')],
        )
        bom = Bom(
            components=[Component(name='c', bom_ref='c')],
            services=[svc],
            data_flows=[
                DataFlowEdge(bom_ref='df-1', source='svc1', target='c', data_ref='data-pii'),
            ],
        )
        msgs = [m for sev, m in _findings_with(bom) if sev == 'warning' and 'flow' in m]
        self.assertTrue(len(msgs) > 0, msgs)
