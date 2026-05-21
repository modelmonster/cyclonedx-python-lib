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

from json import loads as json_loads
from unittest import TestCase

from cyclonedx._internal.aibom_properties import compat_id_from_ref, decode_core_properties, decoded_dataflow_target_id
from cyclonedx.exception import MissingOptionalDependencyException
from cyclonedx.model import DataClassification, DataFlow as ServiceDataFlow, Property
from cyclonedx.model.aibom import (
    AIBOM_PROP_COMPLETENESS,
    AIBOM_PROP_ENCODING,
    AIBOM_PROP_GENERATION_METHOD,
    AIBOM_PROP_GRAPH_TYPE,
    AIBOM_PROP_SCOPE,
    AIBOM_PROP_SPEC_VERSION,
    AibomCompleteness,
    AibomEncoding,
    AibomGraphSelfDescription,
    DataFlowEdge,
    DataFlowOperation,
    TrustZone,
)
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.service import Service
from cyclonedx.output import make_outputter
from cyclonedx.output.aibom import make_aibom_native_bom, make_aibom_outputter, make_aibom_properties_bom
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.validation.xml import XmlValidator


def _self_description() -> AibomGraphSelfDescription:
    return AibomGraphSelfDescription(
        graph_type='system-structure',
        generation_method='declared',
        scope='ai-system',
        completeness=AibomCompleteness.UNKNOWN,
    )


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
                operations=[DataFlowOperation.READ], data_refs=['data-pii'],
                data=[DataClassification(flow=ServiceDataFlow.UNKNOWN, classification='prompt', bom_ref='edge-data')],
            ),
            DataFlowEdge(bom_ref='df:unsafe/2', source='comp1', target='svc1'),
        ],
    )


class TestCorePropertyCodec(TestCase):

    def test_percent_encodes_unsafe_ids(self) -> None:
        self.assertEqual('df%3Aunsafe%2F2', compat_id_from_ref('df:unsafe/2'))

    def test_decoded_dataflow_target_id_is_canonical(self) -> None:
        self.assertEqual('aibom:dataFlow:df-1', decoded_dataflow_target_id('df-1'))

    def test_decodes_generated_dataflow_properties(self) -> None:
        compat = make_aibom_properties_bom(_full_aibom(), self_description=_self_description())
        decoded = decode_core_properties(compat.properties)
        self.assertEqual({'aibom:dataFlow:df-1', 'aibom:dataFlow:df%3Aunsafe%2F2'}, {
            edge.bom_ref.value for edge in decoded.data_flows
        })
        first = next(edge for edge in decoded.data_flows if edge.bom_ref.value == 'aibom:dataFlow:df-1')
        self.assertEqual({'data-pii'}, {ref.value for ref in first.data_refs})
        self.assertEqual({'edge-data'}, {d.bom_ref.value for d in first.data if d.bom_ref is not None})

    def test_decoder_reports_duplicate_operation_before_model_deduplication(self) -> None:
        decoded = decode_core_properties([
            Property(name='aibom:dataFlow:df-1:source', value='a'),
            Property(name='aibom:dataFlow:df-1:target', value='b'),
            Property(name='aibom:dataFlow:df-1:operation', value='read'),
            Property(name='aibom:dataFlow:df-1:operation', value='read'),
        ])
        self.assertEqual(('aibom:dataFlow:df-1',), decoded.duplicate_operations)


class TestPropertiesEncoding(TestCase):

    def test_does_not_mutate_source(self) -> None:
        bom = _full_aibom()
        original_props = list(bom.properties)
        original_data_flows = list(bom.data_flows)
        make_aibom_properties_bom(bom, self_description=_self_description())
        self.assertEqual(original_props, list(bom.properties))
        self.assertEqual(original_data_flows, list(bom.data_flows))

    def test_drops_native_v18_fields_for_v17_output(self) -> None:
        compat = make_aibom_properties_bom(_full_aibom(), self_description=_self_description())
        self.assertEqual(0, len(compat.trust_zones))
        self.assertEqual(0, len(compat.data_flows))

    def test_requires_self_description(self) -> None:
        with self.assertRaisesRegex(ValueError, 'Graph Self-Description'):
            make_aibom_properties_bom(_full_aibom())

    def test_strips_generated_aibom_properties_but_preserves_unknowns(self) -> None:
        bom = _full_aibom()
        stale = Bom(
            components=list(bom.components), services=list(bom.services),
            trust_zones=list(bom.trust_zones), data_flows=list(bom.data_flows),
            properties=[
                Property(name='aibom:dataFlow:df-OLD:source', value='stale'),
                Property(name='aibom:profile', value='full'),
                Property(name='aibom:custom', value='keep'),
            ],
        )
        cleaned = make_aibom_properties_bom(stale, self_description=_self_description())
        prop_names = {p.name for p in cleaned.properties}
        self.assertNotIn('aibom:dataFlow:df-OLD:source', prop_names)
        self.assertNotIn('aibom:profile', prop_names)
        self.assertIn('aibom:dataFlow:df-1:source', prop_names)
        self.assertIn('aibom:custom', prop_names)

    def test_idempotent_on_same_input(self) -> None:
        bom = _full_aibom()
        out1 = make_aibom_properties_bom(bom, self_description=_self_description())
        out2 = make_aibom_properties_bom(bom, self_description=_self_description())
        self.assertEqual(
            sorted((p.name, p.value) for p in out1.properties),
            sorted((p.name, p.value) for p in out2.properties),
        )

    def test_emits_self_description_properties(self) -> None:
        compat = make_aibom_properties_bom(_full_aibom(), self_description=_self_description())
        props = {p.name: p.value for p in compat.properties}
        self.assertEqual('system-structure', props[AIBOM_PROP_GRAPH_TYPE])
        self.assertEqual('declared', props[AIBOM_PROP_GENERATION_METHOD])
        self.assertEqual('ai-system', props[AIBOM_PROP_SCOPE])
        self.assertEqual('unknown', props[AIBOM_PROP_COMPLETENESS])
        self.assertEqual('properties', props[AIBOM_PROP_ENCODING])

    def test_emits_data_descriptor_properties(self) -> None:
        compat = make_aibom_properties_bom(_full_aibom(), self_description=_self_description())
        names = {p.name for p in compat.properties}
        self.assertIn('aibom:data:data-pii:owner', names)
        self.assertIn('aibom:data:data-pii:classification', names)
        self.assertIn('aibom:data:data-pii:flow', names)
        self.assertIn('aibom:dataFlow:df-1:data:edge-data:classification', names)

    def test_emits_component_trust_zone_property(self) -> None:
        compat = make_aibom_properties_bom(_full_aibom(), self_description=_self_description())
        prop_values = {p.name: p.value for p in compat.properties}
        self.assertEqual('internal-vpc', prop_values.get('aibom:node:comp1:trustZone'))

    def test_unreferenced_metadata_component_trust_zone_is_not_encoded_as_node(self) -> None:
        bom = Bom(
            metadata=BomMetaData(component=Component(name='system', bom_ref='system', trust_zone='internal-vpc')),
            components=[Component(name='comp1', bom_ref='comp1')],
            services=[Service(name='svc1', bom_ref='svc1')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='comp1', target='svc1')],
        )
        compat = make_aibom_properties_bom(bom, self_description=_self_description())
        prop_names = {p.name for p in compat.properties}
        self.assertNotIn('aibom:node:system:trustZone', prop_names)

    def test_warns_when_compat_mode_drops_edge_properties(self) -> None:
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1')],
            services=[Service(name='svc1', bom_ref='svc1')],
            data_flows=[
                DataFlowEdge(
                    bom_ref='df-1', source='comp1', target='svc1',
                    properties=[Property(name='reviewed-by', value='security')],
                ),
            ],
        )
        with self.assertWarnsRegex(UserWarning, 'DataFlowEdge.properties'):
            make_aibom_properties_bom(bom, self_description=_self_description())

    def test_rejects_inline_data_without_bom_ref_in_properties_mode(self) -> None:
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1')],
            services=[Service(name='svc1', bom_ref='svc1')],
            data_flows=[
                DataFlowEdge(
                    bom_ref='df-1', source='comp1', target='svc1',
                    data=[DataClassification(flow=ServiceDataFlow.UNKNOWN, classification='prompt')],
                ),
            ],
        )
        with self.assertRaisesRegex(ValueError, 'inline data descriptors'):
            make_aibom_properties_bom(bom, self_description=_self_description())

    def test_preserves_component_dependency_bom_ref_alias(self) -> None:
        shared_ref = BomRef(value='comp1')
        component = Component(name='comp1', bom_ref=shared_ref)
        bom = Bom(
            components=[component],
            services=[Service(name='svc1', bom_ref='svc1')],
            dependencies=[Dependency(ref=shared_ref)],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='comp1', target='svc1')],
        )
        compat = make_aibom_properties_bom(bom, self_description=_self_description())
        compat_component = next(iter(compat.components))
        compat_dependency = next(iter(compat.dependencies))
        self.assertIs(compat_component.bom_ref, compat_dependency.ref)

    def test_shallow_copy_preserves_post_construction_state(self) -> None:
        bom = _full_aibom()
        marker = object()
        bom._future_bom_field = marker  # type: ignore[attr-defined]
        compat = make_aibom_properties_bom(bom, self_description=_self_description())
        self.assertIs(marker, compat._future_bom_field)  # type: ignore[attr-defined]

    def test_shallow_copy_rebuilds_top_level_collections(self) -> None:
        bom = _full_aibom()
        compat = make_aibom_properties_bom(bom, self_description=_self_description())
        self.assertIsNot(bom.components, compat.components)
        compat.components.add(Component(name='new-comp', bom_ref='new-comp'))
        self.assertEqual({'comp1'}, {c.bom_ref.value for c in bom.components})


class TestNativeEncoding(TestCase):

    def test_native_preserves_aibom_fields(self) -> None:
        out = make_aibom_native_bom(_full_aibom(), self_description=_self_description())
        self.assertEqual(2, len(out.trust_zones))
        self.assertEqual(2, len(out.data_flows))

    def test_native_adds_self_description_properties(self) -> None:
        out = make_aibom_native_bom(_full_aibom(), self_description=_self_description())
        props = {p.name: p.value for p in out.properties}
        self.assertEqual('0.1-draft', props[AIBOM_PROP_SPEC_VERSION])
        self.assertEqual('native', props[AIBOM_PROP_ENCODING])
        self.assertEqual('system-structure', props[AIBOM_PROP_GRAPH_TYPE])
        self.assertNotIn('aibom:profile', props)

    def test_native_copy_preserves_post_construction_state(self) -> None:
        bom = _full_aibom()
        marker = object()
        bom._future_bom_field = marker  # type: ignore[attr-defined]
        native = make_aibom_native_bom(bom, self_description=_self_description())
        self.assertIs(marker, native._future_bom_field)  # type: ignore[attr-defined]

    def test_native_copy_rebuilds_top_level_collections(self) -> None:
        bom = _full_aibom()
        native = make_aibom_native_bom(bom, self_description=_self_description())
        self.assertIsNot(bom.data_flows, native.data_flows)
        native.data_flows.add(DataFlowEdge(bom_ref='df-new', source='comp1', target='svc1'))
        self.assertEqual({'df-1', 'df:unsafe/2'}, {e.bom_ref.value for e in bom.data_flows})


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
            self_description=_self_description(),
        ).output_as_string()
        parsed = json_loads(out)
        self.assertIn('dataFlows', parsed)
        self.assertIn('trustZones', parsed)
        self.assertIn('dataRefs', parsed['dataFlows'][0])
        self._validate_json(SchemaVersion.V1_8, out)

    def test_native_v18_xml_valid(self) -> None:
        out = make_aibom_outputter(
            _full_aibom(), OutputFormat.XML,
            schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.NATIVE,
            self_description=_self_description(),
        ).output_as_string()
        self.assertIn('<dataFlows>', out)
        self.assertIn('<trustZones>', out)
        self._validate_xml(SchemaVersion.V1_8, out)

    def test_properties_v17_json_valid(self) -> None:
        out = make_aibom_outputter(
            _full_aibom(), OutputFormat.JSON,
            schema_version=SchemaVersion.V1_7, encoding=AibomEncoding.PROPERTIES,
            self_description=_self_description(),
        ).output_as_string()
        parsed = json_loads(out)
        self.assertNotIn('dataFlows', parsed)
        self.assertNotIn('trustZones', parsed)
        self.assertEqual('1.7', parsed['specVersion'])
        prop_names = {p['name'] for p in parsed['properties']}
        self.assertIn('aibom:dataFlow:df-1:source', prop_names)
        self.assertIn('aibom:dataFlow:df%3Aunsafe%2F2:source', prop_names)
        self.assertEqual('public-internet', parsed['services'][0]['trustZone'])
        self._validate_json(SchemaVersion.V1_7, out)

    def test_properties_v17_xml_valid(self) -> None:
        out = make_aibom_outputter(
            _full_aibom(), OutputFormat.XML,
            schema_version=SchemaVersion.V1_7, encoding=AibomEncoding.PROPERTIES,
            self_description=_self_description(),
        ).output_as_string()
        self.assertNotIn('<dataFlows>', out)
        self.assertNotIn('<trustZones>', out)
        self._validate_xml(SchemaVersion.V1_7, out)

    def test_native_v17_rejected(self) -> None:
        with self.assertRaises(ValueError):
            make_aibom_outputter(
                _full_aibom(), OutputFormat.JSON,
                schema_version=SchemaVersion.V1_7, encoding=AibomEncoding.NATIVE,
                self_description=_self_description(),
            )

    def test_properties_v18_rejected(self) -> None:
        with self.assertRaises(ValueError):
            make_aibom_outputter(
                _full_aibom(), OutputFormat.JSON,
                schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.PROPERTIES,
                self_description=_self_description(),
            )

    def test_aibom_helper_rejects_trust_zones_without_data_flows(self) -> None:
        bom = Bom(
            components=[Component(name='comp1', bom_ref='comp1', trust_zone='internal-vpc')],
            trust_zones=[TrustZone(name='internal-vpc')],
        )
        with self.assertRaisesRegex(ValueError, 'AIBOM output requires at least one data flow'):
            make_aibom_outputter(
                bom, OutputFormat.JSON,
                schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.NATIVE,
                self_description=_self_description(),
            )

    def test_generic_v18_output_does_not_add_self_description_properties(self) -> None:
        bom = _full_aibom()
        generic_out = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_8).output_as_string()
        helper_out = make_aibom_outputter(
            bom, OutputFormat.JSON,
            schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.NATIVE,
            self_description=_self_description(),
        ).output_as_string()
        generic_props = json_loads(generic_out).get('properties', [])
        helper_props = json_loads(helper_out)['properties']
        self.assertEqual([], [p for p in generic_props if p['name'].startswith('aibom:')])
        self.assertIn(AIBOM_PROP_GRAPH_TYPE, {p['name'] for p in helper_props})
        self.assertEqual(0, len(bom.properties))

    def test_semantic_errors_block_output_by_default(self) -> None:
        bom = Bom(
            services=[Service(name='svc1', bom_ref='svc1')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='ghost', target='svc1')],
        )
        with self.assertRaisesRegex(ValueError, 'AIBOM semantic validation failed: .*ghost'):
            make_aibom_outputter(
                bom, OutputFormat.JSON,
                schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.NATIVE,
                self_description=_self_description(),
            )

    def test_semantic_validation_can_be_disabled(self) -> None:
        bom = Bom(
            services=[Service(name='svc1', bom_ref='svc1')],
            data_flows=[DataFlowEdge(bom_ref='df-1', source='ghost', target='svc1')],
        )
        out = make_aibom_outputter(
            bom, OutputFormat.JSON,
            schema_version=SchemaVersion.V1_8, encoding=AibomEncoding.NATIVE,
            self_description=_self_description(),
            validate_semantics=False,
        ).output_as_string()
        self.assertIn('ghost', out)
