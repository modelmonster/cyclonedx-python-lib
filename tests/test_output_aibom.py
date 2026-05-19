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

from io import StringIO
from json import loads as json_loads
from unittest import TestCase

from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.model import DataClassification, DataFlow as ServiceDataFlow, Property
from cyclonedx.model.aibom import DataFlowEdge, DataFlowOperation, TrustZone
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.service import Service
from cyclonedx.output.aibom import (
    AibomEncoding,
    AibomProfile,
    infer_profile,
    make_aibom_native_bom,
    make_aibom_outputter,
    make_aibom_properties_bom,
)
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.validation.xml import XmlValidator


def _full_aibom() -> Bom:
    svc = Service(
        name='svc1', bom_ref='svc1', trust_zone='public-internet',
        data=[DataClassification(flow=ServiceDataFlow.OUTBOUND, classification='PII', bom_ref='data-pii')],
    )
    return Bom(
        components=[Component(name='comp1', bom_ref='comp1', trust_zone='internal-vpc')],
        services=[svc],
        trust_zones=[
            TrustZone(name='internal-vpc', default=True),
            TrustZone(name='public-internet'),
        ],
        data_flows=[
            DataFlowEdge(
                bom_ref='df-1', source='svc1', target='comp1',
                operations=[DataFlowOperation.READ], data_ref='data-pii',
            ),
            DataFlowEdge(bom_ref='df-2', source='comp1', target='svc1'),
        ],
    )


class TestProfileInference(TestCase):

    def test_full_profile_with_data_ref_and_zone(self) -> None:
        self.assertEqual(AibomProfile.FULL, infer_profile(_full_aibom()))

    def test_classified_profile_with_data_ref_only(self) -> None:
        svc = Service(
            name='svc1', bom_ref='svc1',
            data=[DataClassification(flow=ServiceDataFlow.OUTBOUND, classification='PII', bom_ref='data-pii')],
        )
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1')],
            services=[svc],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='comp1', target='svc1', data_ref='data-pii')],
        )
        self.assertEqual(AibomProfile.CLASSIFIED, infer_profile(bom))

    def test_zoned_profile_without_data_ref(self) -> None:
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1', trust_zone='internal-vpc')],
            services=[Service(name='svc1', bom_ref='svc1')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='comp1', target='svc1')],
        )
        self.assertEqual(AibomProfile.ZONED, infer_profile(bom))

    def test_core_profile_with_only_data_flows(self) -> None:
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1')],
            services=[Service(name='svc1', bom_ref='svc1')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='comp1', target='svc1')],
        )
        self.assertEqual(AibomProfile.CORE, infer_profile(bom))

    def test_no_inference_without_data_flows(self) -> None:
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1', trust_zone='internal-vpc')],
            trust_zones=[TrustZone(name='internal-vpc')],
        )
        self.assertIsNone(infer_profile(bom))


class TestPropertiesEncoding(TestCase):

    def test_does_not_mutate_source(self) -> None:
        bom = _full_aibom()
        original_props = list(bom.properties)
        original_data_flows = list(bom.data_flows)
        make_aibom_properties_bom(bom)
        self.assertEqual(original_props, list(bom.properties))
        self.assertEqual(original_data_flows, list(bom.data_flows))

    def test_drops_native_v18_fields_for_v17_output(self) -> None:
        bom = _full_aibom()
        compat = make_aibom_properties_bom(bom)
        self.assertEqual(0, len(compat.trust_zones))
        self.assertEqual(0, len(compat.data_flows))

    def test_strips_stale_aibom_properties(self) -> None:
        bom = _full_aibom()
        # inject a stale aibom: property on a copy
        stale = Bom(
            components=list(bom.components), services=list(bom.services),
            trust_zones=list(bom.trust_zones), data_flows=list(bom.data_flows),
            properties=[Property(name='aibom:dataFlow:df-OLD:source', value='stale')],
        )
        cleaned = make_aibom_properties_bom(stale)
        prop_names = {p.name for p in cleaned.properties}
        self.assertNotIn('aibom:dataFlow:df-OLD:source', prop_names)
        self.assertIn('aibom:dataFlow:df-1:source', prop_names)

    def test_idempotent_on_same_input(self) -> None:
        bom = _full_aibom()
        out1 = make_aibom_properties_bom(bom)
        out2 = make_aibom_properties_bom(bom)
        self.assertEqual(
            sorted((p.name, p.value) for p in out1.properties),
            sorted((p.name, p.value) for p in out2.properties),
        )

    def test_emits_data_descriptor_properties(self) -> None:
        compat = make_aibom_properties_bom(_full_aibom())
        names = {p.name for p in compat.properties}
        self.assertIn('aibom:data:data-pii:owner', names)
        self.assertIn('aibom:data:data-pii:classification', names)
        self.assertIn('aibom:data:data-pii:flow', names)

    def test_emits_component_trust_zone_property(self) -> None:
        compat = make_aibom_properties_bom(_full_aibom())
        prop_values = {p.name: p.value for p in compat.properties}
        self.assertEqual('internal-vpc', prop_values.get('aibom:node:comp1:trustZone'))


class TestNativeEncoding(TestCase):

    def test_native_preserves_aibom_fields(self) -> None:
        out = make_aibom_native_bom(_full_aibom())
        self.assertEqual(2, len(out.trust_zones))
        self.assertEqual(2, len(out.data_flows))

    def test_native_adds_discovery_properties(self) -> None:
        out = make_aibom_native_bom(_full_aibom())
        names = {p.name for p in out.properties}
        self.assertIn('aibom:specVersion', names)
        self.assertIn('aibom:encoding', names)
        self.assertIn('aibom:profile', names)
        prop_values = {p.name: p.value for p in out.properties}
        self.assertEqual('native', prop_values['aibom:encoding'])


class TestMakeAibomOutputter(TestCase):

    def _validate_json(self, schema_version: SchemaVersion, output_text: str) -> None:
        try:
            errors = JsonStrictValidator(schema_version).validate_str(output_text)
        except MissingOptionalDependencyException:
            self.skipTest('MissingOptionalDependencyException')
        self.assertIsNone(errors, output_text)

    def _validate_xml(self, schema_version: SchemaVersion, output_text: str) -> None:
        try:
            errors = XmlValidator(schema_version).validate_str(output_text)
        except MissingOptionalDependencyException:
            self.skipTest('MissingOptionalDependencyException')
        self.assertIsNone(errors, output_text)

    def test_native_v18_json_valid(self) -> None:
        out = make_aibom_outputter(
            _full_aibom(), OutputFormat.JSON,
            schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.NATIVE,
        ).output_as_string()
        parsed = json_loads(out)
        self.assertIn('dataFlows', parsed)
        self.assertIn('trustZones', parsed)
        self._validate_json(SchemaVersion.V1_8, out)

    def test_native_v18_xml_valid(self) -> None:
        out = make_aibom_outputter(
            _full_aibom(), OutputFormat.XML,
            schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.NATIVE,
        ).output_as_string()
        self.assertIn('<dataFlows>', out)
        self.assertIn('<trustZones>', out)
        self._validate_xml(SchemaVersion.V1_8, out)

    def test_properties_v17_json_valid(self) -> None:
        out = make_aibom_outputter(
            _full_aibom(), OutputFormat.JSON,
            schema_version=SchemaVersion.V1_7, encoding=AibomEncoding.PROPERTIES,
        ).output_as_string()
        parsed = json_loads(out)
        self.assertNotIn('dataFlows', parsed)
        self.assertNotIn('trustZones', parsed)
        self.assertEqual('1.7', parsed['specVersion'])
        self._validate_json(SchemaVersion.V1_7, out)

    def test_properties_v17_xml_valid(self) -> None:
        out = make_aibom_outputter(
            _full_aibom(), OutputFormat.XML,
            schema_version=SchemaVersion.V1_7, encoding=AibomEncoding.PROPERTIES,
        ).output_as_string()
        self.assertNotIn('<dataFlows>', out)
        self.assertNotIn('<trustZones>', out)
        self._validate_xml(SchemaVersion.V1_7, out)

    def test_native_v17_rejected(self) -> None:
        with self.assertRaises(ValueError):
            make_aibom_outputter(
                _full_aibom(), OutputFormat.JSON,
                schema_version=SchemaVersion.V1_7, encoding=AibomEncoding.NATIVE,
            )

    def test_properties_v18_rejected(self) -> None:
        with self.assertRaises(ValueError):
            make_aibom_outputter(
                _full_aibom(), OutputFormat.JSON,
                schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.PROPERTIES,
            )


class TestRoundtrip(TestCase):

    def test_native_v18_json_to_xml_roundtrip(self) -> None:
        bom = _full_aibom()
        json_out = make_aibom_outputter(
            bom, OutputFormat.JSON,
            schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.NATIVE,
        ).output_as_string()
        from_json = Bom.from_json(json_loads(json_out))
        # ...then serialize as XML and read back
        xml_out = make_aibom_outputter(
            from_json, OutputFormat.XML,
            schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.NATIVE,
        ).output_as_string()
        from_xml = Bom.from_xml(StringIO(xml_out))
        self.assertEqual(2, len(from_xml.data_flows))
        self.assertEqual(2, len(from_xml.trust_zones))
