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

from sortedcontainers import SortedSet

from cyclonedx.model import DataClassification, DataFlow as ServiceDataFlow, Property
from cyclonedx.model.aibom import (
    AIBOM_PROP_COMPLETENESS,
    AIBOM_PROP_GENERATION_METHOD,
    AIBOM_PROP_GRAPH_TYPE,
    AIBOM_PROP_SCOPE,
    AibomCompleteness,
    AibomGraphSelfDescription,
    DataFlowEdge,
    DataFlowOperation,
    TrustZone,
)
from cyclonedx.model.bom_ref import BomRef


class TestDataFlowOperation(TestCase):

    def test_enum_values(self) -> None:
        self.assertEqual('read', DataFlowOperation.READ.value)
        self.assertEqual('write', DataFlowOperation.WRITE.value)
        self.assertEqual('execute', DataFlowOperation.EXECUTE.value)
        self.assertEqual('delete', DataFlowOperation.DELETE.value)


class TestTrustZone(TestCase):

    def test_minimal(self) -> None:
        tz = TrustZone(name='internal-vpc')
        self.assertEqual('internal-vpc', tz.name)
        self.assertIsNone(tz.description)
        self.assertIsNone(tz.default)

    def test_full(self) -> None:
        tz = TrustZone(name='public-internet', description='Untrusted', default=True)
        self.assertTrue(tz.default)
        self.assertEqual('Untrusted', tz.description)

    def test_empty_name_rejected(self) -> None:
        with self.assertRaises(ValueError):
            TrustZone(name='')

    def test_equality_and_sorted_set(self) -> None:
        a = TrustZone(name='zone-a')
        b = TrustZone(name='zone-b')
        c = TrustZone(name='zone-a', description='changed')
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(3, len(SortedSet((a, b, c))))


class TestAibomGraphSelfDescription(TestCase):

    def test_as_properties(self) -> None:
        desc = AibomGraphSelfDescription(
            graph_type='system-structure',
            generation_method='declared',
            scope='ai-system',
            completeness=AibomCompleteness.UNKNOWN,
        )
        props = {p.name: p.value for p in desc.as_properties()}
        self.assertEqual('system-structure', props[AIBOM_PROP_GRAPH_TYPE])
        self.assertEqual('declared', props[AIBOM_PROP_GENERATION_METHOD])
        self.assertEqual('ai-system', props[AIBOM_PROP_SCOPE])
        self.assertEqual('unknown', props[AIBOM_PROP_COMPLETENESS])

    def test_from_properties(self) -> None:
        desc = AibomGraphSelfDescription.from_properties([
            Property(name=AIBOM_PROP_GRAPH_TYPE, value='system-structure'),
            Property(name=AIBOM_PROP_GENERATION_METHOD, value='observed'),
            Property(name=AIBOM_PROP_SCOPE, value='workflow'),
            Property(name=AIBOM_PROP_COMPLETENESS, value='complete'),
        ])
        self.assertEqual(AibomCompleteness.COMPLETE, desc.completeness)

    def test_rejects_empty_axes(self) -> None:
        with self.assertRaises(ValueError):
            AibomGraphSelfDescription(
                graph_type='',
                generation_method='declared',
                scope='ai-system',
                completeness=AibomCompleteness.UNKNOWN,
            )


class TestDataFlowEdge(TestCase):

    def test_minimal_edge(self) -> None:
        e = DataFlowEdge(bom_ref='df-1', source='a', target='b')
        self.assertEqual('df-1', e.bom_ref.value)
        self.assertEqual('a', e.source.value)
        self.assertEqual('b', e.target.value)
        self.assertEqual(0, len(e.operations))
        self.assertEqual(0, len(e.data_refs))
        self.assertEqual(0, len(e.data))
        self.assertIsNone(e.name)

    def test_with_operations_data_refs_and_inline_data(self) -> None:
        e = DataFlowEdge(
            bom_ref='df-1', source='a', target='b',
            operations=[DataFlowOperation.WRITE, DataFlowOperation.EXECUTE],
            data_refs=['data-1', 'data-2'],
            data=[DataClassification(flow=ServiceDataFlow.UNKNOWN, classification='prompt', bom_ref='edge-data')],
            name='label',
        )
        self.assertEqual({DataFlowOperation.WRITE, DataFlowOperation.EXECUTE}, set(e.operations))
        self.assertEqual({'data-1', 'data-2'}, {r.value for r in e.data_refs})
        self.assertEqual({'edge-data'}, {d.bom_ref.value for d in e.data if d.bom_ref is not None})
        self.assertEqual('label', e.name)

    def test_singular_data_ref_is_python_only_alias(self) -> None:
        e = DataFlowEdge(bom_ref='df-1', source='a', target='b', data_ref='data-1')
        self.assertEqual({'data-1'}, {r.value for r in e.data_refs})

    def test_data_ref_and_data_refs_are_mutually_exclusive(self) -> None:
        with self.assertRaises(ValueError):
            DataFlowEdge(bom_ref='df-1', source='a', target='b', data_ref='x', data_refs=['y'])

    def test_required_refs_reject_empty(self) -> None:
        for arg in ('bom_ref', 'source', 'target'):
            with self.assertRaises(ValueError):
                DataFlowEdge(**{**{'bom_ref': 'x', 'source': 'a', 'target': 'b'}, arg: ''})  # type: ignore[arg-type]

    def test_required_refs_reject_blank_bom_ref(self) -> None:
        with self.assertRaises(ValueError):
            DataFlowEdge(bom_ref=BomRef(), source='a', target='b')

    def test_required_refs_reject_non_string_values(self) -> None:
        with self.assertRaises(ValueError):
            DataFlowEdge(bom_ref=123, source='a', target='b')  # type: ignore[arg-type]

    def test_optional_data_ref_stays_none(self) -> None:
        e = DataFlowEdge(bom_ref='df-1', source='a', target='b')
        self.assertEqual(0, len(e.data_refs))

    def test_equality_by_bom_ref(self) -> None:
        e1 = DataFlowEdge(bom_ref='df-1', source='a', target='b')
        e2 = DataFlowEdge(bom_ref='df-2', source='a', target='b')
        self.assertNotEqual(e1, e2)
        self.assertEqual(2, len(SortedSet((e1, e2))))

    def test_duplicate_operations_deduplicate(self) -> None:
        e = DataFlowEdge(
            bom_ref='df-1', source='a', target='b',
            operations=[DataFlowOperation.READ, DataFlowOperation.READ],
        )
        self.assertEqual([DataFlowOperation.READ], list(e.operations))
