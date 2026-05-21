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
AIBOM System Structure model types.

Implements the typed object model for the AIBOM System Structure specification
(see ``docs/specs/aibom-draft-v1.md``). The native fields are
gated to ``SchemaVersion.V1_8`` only.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, Union

import py_serializable as serializable
from sortedcontainers import SortedSet

from .._internal.bom_ref import bom_ref_from_str as _bom_ref_from_str
from .._internal.compare import ComparableTuple as _ComparableTuple
from ..exception.serialization import SerializationOfUnexpectedValueException
from . import DataClassification, Property
from .bom_ref import BomRef

AIBOM_SPEC_VERSION_DEFAULT = '0.1-draft'
AIBOM_PROPERTY_PREFIX = 'aibom:'
AIBOM_PROP_SPEC_VERSION = f'{AIBOM_PROPERTY_PREFIX}specVersion'
AIBOM_PROP_ENCODING = f'{AIBOM_PROPERTY_PREFIX}encoding'
AIBOM_PROP_GRAPH_TYPE = f'{AIBOM_PROPERTY_PREFIX}graphType'
AIBOM_PROP_GENERATION_METHOD = f'{AIBOM_PROPERTY_PREFIX}generationMethod'
AIBOM_PROP_SCOPE = f'{AIBOM_PROPERTY_PREFIX}scope'
AIBOM_PROP_COMPLETENESS = f'{AIBOM_PROPERTY_PREFIX}completeness'
AIBOM_PROP_TRUST_PERSPECTIVE = f'{AIBOM_PROPERTY_PREFIX}trustPerspective'
AIBOM_PROP_SYSTEM_RELATIONSHIP = f'{AIBOM_PROPERTY_PREFIX}systemRelationship'
AIBOM_PROP_MODEL_REF = f'{AIBOM_PROPERTY_PREFIX}modelRef'
AIBOM_PROP_SERVICE_ROLE = f'{AIBOM_PROPERTY_PREFIX}serviceRole'
AIBOM_SERVICE_ROLE_MODEL_SERVING = 'model-serving'


class AibomEncoding(str, Enum):
    """Output encoding mode for AIBOM payloads."""
    NATIVE = 'native'
    PROPERTIES = 'properties'


class AibomCompleteness(str, Enum):
    """AIBOM completeness values aligned with CycloneDX aggregateType semantics."""
    COMPLETE = 'complete'
    INCOMPLETE = 'incomplete'
    INCOMPLETE_FIRST_PARTY_ONLY = 'incomplete_first_party_only'
    INCOMPLETE_FIRST_PARTY_PROPRIETARY_ONLY = 'incomplete_first_party_proprietary_only'
    INCOMPLETE_FIRST_PARTY_OPENSOURCE_ONLY = 'incomplete_first_party_opensource_only'
    INCOMPLETE_THIRD_PARTY_ONLY = 'incomplete_third_party_only'
    INCOMPLETE_THIRD_PARTY_PROPRIETARY_ONLY = 'incomplete_third_party_proprietary_only'
    INCOMPLETE_THIRD_PARTY_OPENSOURCE_ONLY = 'incomplete_third_party_opensource_only'
    UNKNOWN = 'unknown'
    NOT_SPECIFIED = 'not_specified'


class AibomSystemRelationship(str, Enum):
    """Scope-relative system membership values for ``aibom:systemRelationship``."""
    CONSTITUENT = 'constituent'
    EXTERNAL = 'external'


def _require_non_empty_string(field: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{field} must be a non-empty string')
    return value


@dataclass(frozen=True)
class AibomGraphSelfDescription:
    """Required Graph Self-Description axes for an AIBOM graph, per draft A1."""
    graph_type: str
    generation_method: str
    scope: str
    completeness: AibomCompleteness

    def __post_init__(self) -> None:
        object.__setattr__(self, 'graph_type', _require_non_empty_string('graph_type', self.graph_type))
        object.__setattr__(
            self, 'generation_method',
            _require_non_empty_string('generation_method', self.generation_method),
        )
        object.__setattr__(self, 'scope', _require_non_empty_string('scope', self.scope))

    def as_properties(self) -> list[Property]:
        return [
            Property(name=AIBOM_PROP_GRAPH_TYPE, value=self.graph_type),
            Property(name=AIBOM_PROP_GENERATION_METHOD, value=self.generation_method),
            Property(name=AIBOM_PROP_SCOPE, value=self.scope),
            Property(name=AIBOM_PROP_COMPLETENESS, value=self.completeness.value),
        ]

    @classmethod
    def from_properties(cls, properties: Iterable[Property]) -> 'AibomGraphSelfDescription':
        values = {
            p.name: _require_non_empty_string(p.name, p.value)
            for p in properties
            if p.value is not None
        }
        missing = [
            name for name in (
                AIBOM_PROP_GRAPH_TYPE,
                AIBOM_PROP_GENERATION_METHOD,
                AIBOM_PROP_SCOPE,
                AIBOM_PROP_COMPLETENESS,
            ) if name not in values
        ]
        if missing:
            raise ValueError(f'AIBOM Graph Self-Description is missing: {", ".join(missing)}')
        return cls(
            graph_type=values[AIBOM_PROP_GRAPH_TYPE],
            generation_method=values[AIBOM_PROP_GENERATION_METHOD],
            scope=values[AIBOM_PROP_SCOPE],
            completeness=AibomCompleteness(values[AIBOM_PROP_COMPLETENESS]),
        )


class _XsdBoolean(serializable.helpers.BaseHelper):
    """  THIS CLASS IS NON-PUBLIC API

    Serializes :class:`bool`:

    * In JSON, keeps the native ``true`` / ``false`` literal.
    * In XML, emits the ``xs:boolean`` lexical space ``"true"`` / ``"false"``,
      because :func:`str` on a Python :class:`bool` would otherwise produce
      ``"True"`` / ``"False"``, which is not a valid ``xs:boolean`` value.
    """

    @classmethod
    def json_serialize(cls, o: Any) -> Optional[bool]:
        if o is None:
            return None
        if isinstance(o, bool):
            return o
        raise ValueError(f'Attempt to serialize a non-bool as xs:boolean: {o.__class__}')

    @classmethod
    def json_deserialize(cls, o: Any) -> Optional[bool]:
        return cls._deserialize(o)

    @classmethod
    def xml_serialize(cls, o: Any) -> Optional[str]:
        if o is None:
            return None
        if isinstance(o, bool):
            return 'true' if o else 'false'
        raise ValueError(f'Attempt to serialize a non-bool as xs:boolean: {o.__class__}')

    @classmethod
    def xml_deserialize(cls, o: Any) -> Optional[bool]:
        return cls._deserialize(o)

    @staticmethod
    def _deserialize(o: Any) -> Optional[bool]:
        if o is None:
            return None
        if isinstance(o, bool):
            return o
        if isinstance(o, str):
            v = o.strip().lower()
            if v in ('true', '1'):
                return True
            if v in ('false', '0'):
                return False
        raise ValueError(f'Cannot deserialize xs:boolean from: {o!r}')


class _BomRefRepositorySerializationHelper(serializable.helpers.BaseHelper):
    """  THIS CLASS IS NON-PUBLIC API  """

    @classmethod
    def serialize(cls, o: Any) -> list[str]:
        if isinstance(o, (SortedSet, set, list, tuple)):
            return [str(i) for i in o]
        raise SerializationOfUnexpectedValueException(
            f'Attempt to serialize a non-BomRef collection: {o!r}')

    @classmethod
    def deserialize(cls, o: Any) -> 'SortedSet[BomRef]':
        refs: 'SortedSet[BomRef]' = SortedSet()
        if isinstance(o, list):
            for v in o:
                ref = _bom_ref_from_str(v, optional=True)
                if ref is not None:
                    refs.add(ref)
        return refs


@serializable.serializable_enum
class DataFlowOperation(str, Enum):
    """
    Operation type for an AIBOM dataflow edge.

    See AIBOM System Structure specification, section 6.4.
    """
    READ = 'read'
    WRITE = 'write'
    EXECUTE = 'execute'
    DELETE = 'delete'


@serializable.serializable_class
class TrustZone:
    """
    A named environment or security boundary referenced by AIBOM graph nodes.

    See AIBOM System Structure specification, section 5.
    """

    def __init__(
        self, *,
        name: str,
        description: Optional[str] = None,
        default: Optional[bool] = None,
    ) -> None:
        if not name:
            raise ValueError('TrustZone.name must be a non-empty string')
        self.name = name
        self.description = description
        self.default = default

    @property
    @serializable.xml_sequence(1)
    @serializable.xml_string(serializable.XmlStringSerializationType.NORMALIZED_STRING)
    def name(self) -> str:
        """
        The name of the trust zone, referenced by `trustZone` on components and services.

        Returns:
            `str`
        """
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        self._name = name

    @property
    @serializable.xml_sequence(2)
    @serializable.xml_string(serializable.XmlStringSerializationType.NORMALIZED_STRING)
    def description(self) -> Optional[str]:
        """
        A short description of the trust zone.

        Returns:
            `str` if set else `None`
        """
        return self._description

    @description.setter
    def description(self, description: Optional[str]) -> None:
        self._description = description

    @property
    @serializable.type_mapping(_XsdBoolean)
    @serializable.xml_attribute()
    def default(self) -> Optional[bool]:
        """
        When true, this trust zone applies to graph nodes that do not declare their own ``trustZone``.
        At most one trust zone entry per BOM may set ``default`` to true.

        Returns:
            `bool` if set else `None`
        """
        return self._default

    @default.setter
    def default(self, default: Optional[bool]) -> None:
        self._default = default

    def __comparable_tuple(self) -> _ComparableTuple:
        return _ComparableTuple((
            self.name, self.description, self.default,
        ))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TrustZone):
            return self.__comparable_tuple() == other.__comparable_tuple()
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, TrustZone):
            return self.__comparable_tuple() < other.__comparable_tuple()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__comparable_tuple())

    def __repr__(self) -> str:
        return f'<TrustZone name={self.name!r}, default={self.default}>'


@serializable.serializable_class
class DataFlowEdge:
    """
    A directed edge in the AIBOM system structure graph, representing data movement
    from a source node to a target node.

    See AIBOM System Structure specification, section 6.

    ``source`` and ``target`` SHALL always define the direction of actual data
    movement. ``operations`` annotate the interaction context but never reverse
    or override edge direction.
    """

    def __init__(
        self, *,
        bom_ref: Union[str, BomRef],
        source: Union[str, BomRef],
        target: Union[str, BomRef],
        operations: Optional[Iterable[DataFlowOperation]] = None,
        data_refs: Optional[Iterable[Union[str, BomRef]]] = None,
        data_ref: Optional[Union[str, BomRef]] = None,
        data: Optional[Iterable[DataClassification]] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        properties: Optional[Iterable[Property]] = None,
    ) -> None:
        if data_ref is not None and data_refs is not None:
            raise ValueError('DataFlowEdge cannot receive both data_ref and data_refs')
        self._bom_ref = self._require_ref('bom_ref', bom_ref)
        self._source = self._require_ref('source', source)
        self._target = self._require_ref('target', target)
        self.operations = operations or []
        self.data_refs = [data_ref] if data_ref is not None else data_refs or []
        self.data = data or []
        self.name = name
        self.description = description
        self.properties = properties or []

    @staticmethod
    def _require_ref(field: str, value: Union[str, BomRef]) -> BomRef:
        if isinstance(value, BomRef):
            if not value.value:
                raise ValueError(f'DataFlowEdge.{field} must be a non-empty BomRef')
            return value
        if isinstance(value, str):
            if not value:
                raise ValueError(f'DataFlowEdge.{field} must be a non-empty string or BomRef')
            return BomRef(value=value)
        else:
            raise ValueError(f'DataFlowEdge.{field} must be a non-empty string or BomRef')

    @property
    @serializable.json_name('bom-ref')
    @serializable.type_mapping(BomRef)
    @serializable.xml_attribute()
    @serializable.xml_name('bom-ref')
    def bom_ref(self) -> BomRef:
        """
        Unique identifier for this dataflow edge. Required.

        Returns:
            `BomRef`
        """
        return self._bom_ref

    @property
    @serializable.type_mapping(BomRef)
    @serializable.xml_sequence(1)
    def source(self) -> BomRef:
        """
        BOM reference of the source node — the component or service from which data moves.

        Returns:
            `BomRef`
        """
        return self._source

    @source.setter
    def source(self, source: Union[str, BomRef]) -> None:
        self._source = self._require_ref('source', source)

    @property
    @serializable.type_mapping(BomRef)
    @serializable.xml_sequence(2)
    def target(self) -> BomRef:
        """
        BOM reference of the target node — the component or service to which data moves.

        Returns:
            `BomRef`
        """
        return self._target

    @target.setter
    def target(self, target: Union[str, BomRef]) -> None:
        self._target = self._require_ref('target', target)

    @property
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'operation')
    @serializable.xml_sequence(3)
    def operations(self) -> 'SortedSet[DataFlowOperation]':
        """
        Operation types annotating the interaction context. Operations never determine,
        reverse, or override edge direction.

        Returns:
            Set of `DataFlowOperation`
        """
        return self._operations

    @operations.setter
    def operations(self, operations: Iterable[DataFlowOperation]) -> None:
        self._operations = SortedSet(operations)

    @property
    @serializable.json_name('dataRefs')
    @serializable.type_mapping(_BomRefRepositorySerializationHelper)
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'dataRef')
    @serializable.xml_sequence(4)
    def data_refs(self) -> 'SortedSet[BomRef]':
        """
        BOM references of data descriptors for payloads on this edge. Each
        reference resolves to endpoint service data or inline edge data.

        Returns:
            Set of `BomRef`
        """
        return self._data_refs

    @data_refs.setter
    def data_refs(self, data_refs: Iterable[Union[str, BomRef]]) -> None:
        refs: 'SortedSet[BomRef]' = SortedSet()
        for data_ref in data_refs:
            refs.add(self._require_ref('data_refs', data_ref))
        self._data_refs = refs

    @property
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'data')
    @serializable.xml_sequence(5)
    def data(self) -> 'SortedSet[DataClassification]':
        """
        Inline data descriptors for payloads on this edge.

        Returns:
            Set of `DataClassification`
        """
        return self._data

    @data.setter
    def data(self, data: Iterable[DataClassification]) -> None:
        self._data = SortedSet(data)

    @property
    @serializable.xml_sequence(6)
    @serializable.xml_string(serializable.XmlStringSerializationType.NORMALIZED_STRING)
    def name(self) -> Optional[str]:
        """
        Human-readable label for this dataflow.

        Returns:
            `str` if set else `None`
        """
        return self._name

    @name.setter
    def name(self, name: Optional[str]) -> None:
        self._name = name

    @property
    @serializable.xml_sequence(7)
    @serializable.xml_string(serializable.XmlStringSerializationType.NORMALIZED_STRING)
    def description(self) -> Optional[str]:
        """
        Description of what data moves on this edge.

        Returns:
            `str` if set else `None`
        """
        return self._description

    @description.setter
    def description(self, description: Optional[str]) -> None:
        self._description = description

    @property
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'property')
    @serializable.xml_sequence(8)
    def properties(self) -> 'SortedSet[Property]':
        """
        Extension properties for this dataflow edge.

        Returns:
            Set of `Property`
        """
        return self._properties

    @properties.setter
    def properties(self, properties: Iterable[Property]) -> None:
        self._properties = SortedSet(properties)

    def __comparable_tuple(self) -> _ComparableTuple:
        return _ComparableTuple((
            self._bom_ref.value,
            self._source.value,
            self._target.value,
            _ComparableTuple(self._operations),
            _ComparableTuple(self._data_refs),
            _ComparableTuple(self._data),
            self.name, self.description,
            _ComparableTuple(self._properties),
        ))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, DataFlowEdge):
            return self.__comparable_tuple() == other.__comparable_tuple()
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, DataFlowEdge):
            return self.__comparable_tuple() < other.__comparable_tuple()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__comparable_tuple())

    def __repr__(self) -> str:
        return f'<DataFlowEdge bom-ref={self._bom_ref.value!r}, {self._source.value!r} -> {self._target.value!r}>'
