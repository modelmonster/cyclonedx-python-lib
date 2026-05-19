# AIBOM System Structure Extension

**Status:** Draft for Discussion
**Author:** Van Lindberg
**Date:** 2026-05-18
**Target Standard:** CycloneDX (ECMA-424) / OWASP AIBOM

---

## Abstract

This document defines a system structure for the AI Bill of Materials
(AIBOM). The extension represents an AI system as a directed graph
of identified nodes connected by dataflows — directed edges that
optionally carry operation types.

The extension reuses existing CycloneDX node primitives (`components[]`
and `services[]`) and preserves the existing meaning of `dependencies[]`
for software dependency relationships. It introduces two new constructs:
`dataFlows[]` for directed data movement between nodes, and an optional
`trustZones[]` definition array that gives structure to `trustZone`
strings on graph nodes.

Nodes are referenced by BOM reference (`bom-ref`) — the same local
reference identifier BOMs already use. Components may also carry
Package URLs (`purl`) for artifact identity across BOMs. The format
captures structural topology and data movement. While the Architecture
Bill of Materials (ABOM) and Threat Modeling Bill of Materials (TM-BOM)
are outside the scope of this document, the concepts here should be
generally sufficient to represent those concepts as well.

## 1. Scope

This specification defines:

- A `dataFlows[]` array representing directed data movement between
  identified nodes, with optional operation types
- An optional `trustZones[]` definition array
- Conventions for referencing existing CycloneDX service data
  classifications from dataflow entries
- Lifecycle phase conventions for distinguishing design-time from
  operations-time documents

This specification does not define:

- Component type taxonomies or classification schemes
- Extensions to the data.classification labels used in SaaSBOM

## 2. Terms and Definitions

**Node.** An identified element in the system graph. Nodes are existing
BOM entries — components or services — referenced by `bom-ref`.
Components may also carry a PURL for artifact identity across BOMs.

**Component.** An element in the system represented as an entry in
the CycloneDX `components[]` array. Components are either *active*
or *passive*:

- *Active components* are processing elements: an LLM, a guardrail,
  a retriever, an orchestrator, a data processor. They transform,
  route, filter, or generate data.
- *Passive components* are data assets: a dataset, an embedding
  store, a vector index, a prompt template, a training set, a model
  artifact, a log archive. Represented with CycloneDX component
  type `data`.

A component's role may vary by context. A `machine-learning-model`
component is typically active during inference but may appear as a
passive write target in a training pipeline. The active/passive
classification describes the node's primary role in the system; the
dataflow edges determine the role in any specific interaction.

**Service.** A callable, addressable, or externally described
runtime interface: an API, a microservice, a serverless function,
a SaaS platform, a managed database, a user-facing channel, or
other network or intra-process service. Services have endpoints,
may reside in trust zones, and may cross trust boundaries.
Represented as entries in the CycloneDX `services[]` array,
following SaaSBOM conventions (see §10.1).

**Trust Zone.** A named environment or boundary in which nodes
reside. Examples: `public-internet`, `internal-vpc`,
`local-application`. Trust zones describe the security context of
components and services but are not themselves participants in the
dataflow graph.

**Dataflow.** A unidirectional directed edge in the system graph,
representing data movement from a source node to a target node.
The `source` and `target` fields SHALL always define the direction
of actual data movement. Dataflows optionally carry operation types
and may reference data classifications.

**Operation.** A typed annotation on a dataflow edge describing the
interaction context or target-side effect — such as `read`, `write`,
`execute`, or `delete`. Operations SHALL NOT determine, reverse, or
override edge direction. They describe *what kind* of interaction the
data movement represents, not *which way* data moves.

**System Structure Graph.** A directed graph where nodes are identified
BOM entries (components and services) and edges are dataflows.

## 3. Conformance

This proposal defines candidate additions to the CycloneDX object
model for a future CycloneDX 1.8 release. Until adopted, producers
MAY encode equivalent information using registered CycloneDX
properties or an AIBOM-specific profile schema. Native examples in
this document target proposed CycloneDX 1.8 behavior. They are not
valid against unmodified CycloneDX 1.7 schemas. For valid CycloneDX
1.7 output, use Appendix B.

Documents using the proposed native fields (`dataFlows[]`,
`trustZones[]`, `trustZones[].default`, `trustZone` on components,
`bom-ref` on `serviceData`) are not valid against the unmodified
CycloneDX 1.7 JSON schema unless represented through CycloneDX-approved
extension mechanisms or the fields have been adopted into the
CycloneDX schema.

Producers MAY include additional CycloneDX elements (vulnerabilities,
formulation, declarations, etc.) alongside the system structure.

Generic CycloneDX consumers MAY ignore AIBOM fields. AIBOM-conforming
consumers SHALL process the fields required by the AIBOM profile they
claim to support.

AIBOM Core consumers SHALL process `dataFlows[]`. AIBOM Classified
consumers SHALL process `dataRef` linkages. AIBOM Zoned consumers
SHALL process `trustZone` values and `trustZones[]` definitions.

Consumers SHALL treat a dataflow entry without an `operations` field
as a directional dataflow with no operation semantics (see §6.4).

### 3.1 Adoption Dependencies

Native AIBOM output depends on changes outside the unmodified
CycloneDX 1.7 schema. The following list names each dependency and
its current adoption status.

- Top-level `dataFlows[]` array.
  Standard: CycloneDX JSON and XML schemas.
  Required for: native graph edges.
  Status: proposed here; CycloneDX specification issue TBD.
- Top-level `trustZones[]` array with optional `default`.
  Standard: CycloneDX JSON and XML schemas.
  Required for: native trust zone definitions.
  Status: proposed here; CycloneDX specification issue TBD.
- `trustZone` on components.
  Standard: CycloneDX JSON and XML schemas.
  Required for: component trust boundary analysis.
  Status: proposed here; mirrors existing `service.trustZone`;
  CycloneDX specification issue TBD.
- `bom-ref` on `serviceData`.
  Standard: CycloneDX JSON and XML schemas.
  Required for: unambiguous `dataRef` linkage to service data.
  Status: proposed here; CycloneDX specification issue TBD.
- XSD root sequence placement for `trustZones` and `dataFlows`.
  Standard: CycloneDX XML schema.
  Required for: native XML validation.
  Status: proposed here; CycloneDX specification issue TBD.

Until the CycloneDX schema changes are adopted, producers that need
valid CycloneDX 1.7 output SHALL use the compatibility encoding in
Appendix B. Producers MAY use any valid PURL. PURL type selection is
outside the scope of this specification.

### 3.2 Profiles

Implementations MAY support a subset of this specification. The
following profiles are defined:

- **Core:** `dataFlows[]` with `source`, `target`, and optional
  `operations`. This is the minimum for a system structure graph.
- **Classified:** Core plus `dataRef` linkage to service data or
  component data descriptors. Enables data governance analysis.
- **Zoned:** Core plus `trustZone` on nodes and optional
  `trustZones[]` definitions. Enables trust boundary analysis.
- **Full:** All of the above.

The declared profile is a minimum conformance claim, not a promise
that every optional field in that profile appears on every applicable
edge or node. A Core producer SHALL emit `dataFlows[]` entries with
resolvable `source` and `target` values. A Classified producer SHALL
meet Core requirements and MAY include `dataRef` only on edges where a
specific data descriptor is known; it is not required to classify every
edge. A Zoned producer SHALL meet Core requirements and MAY include
node `trustZone` values or `trustZones[]` definitions; it is not
required to assign an explicit trust zone to every node. A Full
producer satisfies both Classified and Zoned requirements.

Producers SHOULD declare the highest profile whose fields they
intentionally emit. A producer that emits `dataRef` SHOULD declare
`classified` or `full`. A producer that emits node `trustZone` values
or `trustZones[]` SHOULD declare `zoned` or `full`.

Producers SHOULD declare the profile in a BOM-level property when
partial conformance is intended:

```json
{
  "properties": [
    { "name": "aibom:profile", "value": "core" }
  ]
}
```

When a profile is declared, AIBOM-aware consumers SHOULD validate the
document against the declared profile and SHOULD report fields outside
that profile as warnings unless a stricter local policy treats them as
errors. When no profile is declared, consumers SHOULD infer the
minimum profile from the fields present and SHOULD report the missing
profile declaration as informational.

### 3.3 Extension Version and Encoding

The CycloneDX `specVersion` field identifies the CycloneDX schema
version, not the AIBOM extension version. Producers SHOULD declare the
AIBOM draft version and encoding using BOM-level properties:

```json
{
  "properties": [
    { "name": "aibom:specVersion", "value": "0.1-draft" },
    { "name": "aibom:encoding", "value": "native" },
    { "name": "aibom:profile", "value": "full" }
  ]
}
```

Valid `aibom:encoding` values are `native` and `properties`. A
CycloneDX 1.7 compatibility document encoded through Appendix B
SHOULD set `aibom:encoding` to `properties`. AIBOM-aware consumers
SHOULD use `aibom:specVersion`, `aibom:encoding`, and `aibom:profile`
to select parsing behavior and determine whether unsupported fields
should be ignored, reported, or treated as validation failures.

## 4. Node Representation

### 4.1 Components

Components SHALL be represented as entries in the CycloneDX
`components[]` array, following existing CycloneDX conventions.

Each component participating in the system structure graph SHALL
include a `bom-ref` attribute. Components SHOULD include a `purl`
when a stable artifact identity exists.

CycloneDX component types relevant to AI systems include
`machine-learning-model`, `application`, `library`, `framework`,
`platform`, and `data`. This specification does not restrict which
component types may participate in the system structure graph.

Components of type `data` represent passive data assets in the
system: datasets, embeddings, vector indexes, prompt templates,
training sets, log archives, and similar artifacts. A component of
type `machine-learning-model` may also appear as a passive node in
certain contexts — for example, as the write target of a training
pipeline. A local FAISS index is a data component; a managed
Pinecone service with endpoints and a trust zone is a service
(see §4.2).

Components MAY include a `trustZone` string identifying the trust
zone in which the component resides, using the same semantics as
the existing `trustZone` field on services (see §4.2).

> **Note:** The CycloneDX component schema does not currently
> define a `trustZone` field. This specification proposes adding
> it as an optional string on components, mirroring the existing
> field on services. Without this field, AIBOM consumers cannot
> determine whether a dataflow between a component and a service
> crosses a trust boundary, since the component's environment is
> unknown.

When a component does not declare a `trustZone`, it inherits the
trust zone whose definition sets `default` to `true`, if one is
present (see §5.2). If neither is specified, the component's trust
zone is undefined.

This specification does not impose additional requirements on
component content beyond what CycloneDX already defines. Producers
are free to include any CycloneDX-valid metadata on components
(model cards, licenses, supplier information, properties, tags, etc.).

### 4.2 Services

Services SHALL be represented as entries in the CycloneDX `services[]`
array, following SaaSBOM conventions (see §10.1).

Each service participating in the system structure graph SHALL include
a `bom-ref` attribute. Services that expose a stable network or
logical endpoint SHOULD include endpoint URIs. Services are identified
by `group`, `name`, and `version` as defined in the CycloneDX service
schema. Services MAY additionally include a PURL in `properties[]` for
cross-BOM artifact correlation (see §4.4 for PURL guidance).

Services MAY include `data[]` entries with `flow` direction and
`classification` as defined in CycloneDX `serviceData`. Dataflow
entries MAY reference these service data entries (see §6.5).

Services MAY include a `trustZone` string identifying the trust zone
in which the service resides. If a `trustZones[]` definition array
is present in the BOM (see §5), the `trustZone` string SHOULD match
the `name` of an entry in that array.

Services MAY include `x-trust-boundary` (boolean) indicating whether
use of the service crosses a trust boundary, as defined in existing
CycloneDX.

### 4.3 Node Identity and Resolution

Nodes are referenced in `dataFlows[]` by their `bom-ref` value.
A `bom-ref` SHALL be unique within the BOM document.

Every `source` and `target` value in a `dataFlows[]` entry SHALL
resolve to the `bom-ref` of a component or service object in the
same BOM document, including nested components and services and
`metadata.component` when that object has a `bom-ref` and is
intentionally used as a graph node. AIBOM-aware semantic validators
SHALL reject a document where a dataflow references a `bom-ref` that
does not exist on a graph node.

A `bom-ref` is instance identity — it identifies a specific node
in *this* graph. A PURL is artifact identity — it identifies a
software package or product. These are not the same thing. A
system topology maps instantiated nodes, not abstract packages.
The same package may be deployed as multiple distinct instances
(e.g., an input guardrail and an output guardrail running the same
library version), each requiring its own `bom-ref`.

For nodes participating in the dataflow graph, `bom-ref` SHALL be
a unique local identifier — a UUID or a domain-specific structured
string. Producers SHALL NOT use a PURL as the `bom-ref` value.
The PURL belongs exclusively in the component's `purl` field for
cross-BOM artifact correlation.

Nodes SHOULD include a `purl` on the component when stable artifact
correlation is useful across related BOM documents. PURLs do not
provide remote graph resolution. A dataflow `source` or `target` SHALL
NOT point directly to a node defined only in another BOM. If a graph
needs to reference an external model, service, or artifact, the
producer SHOULD include a local component or service stub with its own
`bom-ref` and attach correlation metadata such as `purl`,
`externalReferences`, BOM-Link, or Transparency Exchange API
references.

### 4.4 PURL Guidance

Components MAY include any valid Package URL (`purl`) value. This
specification does not define, require, or restrict PURL types.
Producers SHOULD choose the PURL that best identifies the artifact
under normal Package URL rules.

Examples:

- `pkg:pypi/langchain@0.3.1`
- `pkg:huggingface/sentence-transformers/all-MiniLM-L6-v2`
- `pkg:generic/acme.com/input-filter@1.2.0`

## 5. Trust Zones

### 5.1 Definition

A trust zone is a named environment or security boundary. Trust
zones provide context about where nodes reside — whether on the
public internet, within an internal network, on a local machine, or
within a specific cloud VPC.

Trust zones are NOT nodes in the dataflow graph. They are metadata
that describes the operating environment of components and services.

### 5.2 The `trustZones[]` Array (Optional)

A BOM document MAY include a top-level `trustZones[]` array that
defines the trust zones referenced by graph nodes:

```json
{
  "trustZones": [
    {
      "name": "public-internet",
      "description": "Untrusted external network"
    },
    {
      "name": "internal-vpc",
      "description": "Private cloud network with controlled access",
      "default": true
    },
    {
      "name": "local-application",
      "description": "Local machine or application boundary"
    }
  ]
}
```

Each trust zone entry SHALL include a `name` field (string). Each
trust zone entry MAY include a `description` field (string) and a
`default` field (boolean).

A BOM document MAY identify one default trust zone by setting
`default` to `true` on one trust zone entry. At most one trust zone
entry SHALL have `default` set to `true`. The default trust zone
applies to graph nodes — components and services — that do not
declare their own `trustZone`:

```json
{
  "trustZones": [
    { "name": "public-internet", "description": "Untrusted external network" },
    { "name": "internal-vpc", "description": "Private cloud network", "default": true }
  ]
}
```

When a node has no explicit `trustZone` and a default trust zone is
present, the node is considered to reside in the default zone. An
explicit node `trustZone` always takes precedence over the default.
This covers the common case where all internal processing components
and services share a single environment.

AIBOM-aware semantic validators SHALL report more than one
`trustZones[]` entry with `default` set to `true` as an error.

### 5.3 Backward Compatibility

The `trustZone` field on services remains a plain string, as defined
in existing CycloneDX. A service `trustZone` value remains backward
compatible with existing CycloneDX documents whether or not
`trustZones[]` is present.

This specification proposes extending the same `trustZone` field to
components (see §4.1). Component `trustZone` is a proposed CycloneDX
schema addition and is not valid against unmodified CycloneDX 1.7
schemas. Producers that need valid 1.7 output SHALL encode component
trust zones through the compatibility mechanism in Appendix B.

When `trustZones[]` is absent, `trustZone` strings are opaque labels
with no additional structure. This is backward compatible for
services because `service.trustZone` already exists; it is not
backward compatible for components until `component.trustZone` is
adopted into the CycloneDX schema.

When `trustZones[]` is present, it provides definitions for the
`trustZone` strings used on components and services. A `trustZone`
string on a node that does not match any entry in `trustZones[]` is
not a schema error but SHOULD be reported by AIBOM-aware semantic
validators and SHOULD be avoided by producers.

## 6. Dataflows

### 6.1 Definition

A dataflow is a directed edge in the system structure graph,
representing that data moves from a source node to a target node.
Source and target node resolution is defined in §4.3.

Dataflows replace the use of `dependencies[]` for representing data
movement. The existing CycloneDX `dependencies[]` array retains its
standard meaning (software dependency relationships). System structure
uses `dataFlows[]` for a semantically distinct purpose: the physical
or logical movement of data through the system. A single BOM
document MAY include both `dependencies[]` and `dataFlows[]` to
capture build-time supply chain relationships and runtime data
movement in one artifact.

The dataflow graph MAY contain cycles (e.g., an orchestrator that
calls a tool and receives results) and MAY contain parallel edges
between the same pair of nodes (e.g., edges carrying different
operations or data classifications).

### 6.2 The `dataFlows[]` Array

A conforming AIBOM System Structure document SHALL include a
top-level `dataFlows[]` array. Each entry in `dataFlows[]` represents
a single directed edge.

```json
{
  "dataFlows": [
    {
      "bom-ref": "df-1",
      "source": "input-filter",
      "target": "claude-sonnet"
    },
    {
      "bom-ref": "df-2",
      "source": "knowledge-base",
      "target": "kb-retriever",
      "operations": ["read"]
    },
    {
      "bom-ref": "df-3",
      "source": "pii-filter",
      "target": "user-output",
      "operations": ["write"]
    }
  ]
}
```

### 6.3 Dataflow Entry Schema

Each dataflow entry SHALL include:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `bom-ref` | refType | Yes | Unique identifier for this dataflow edge |
| `source` | refLinkType | Yes | Source node `bom-ref`; SHALL resolve by §4.3 |
| `target` | refLinkType | Yes | Target node `bom-ref`; SHALL resolve by §4.3 |
| `operations` | array of string | No | Operation types (see §6.4) |
| `dataRef` | refLinkType | No | `bom-ref` of a descriptor for the payload on this edge (see §6.5) |
| `name` | string | No | Human-readable label for this dataflow |
| `description` | string | No | Description of what data moves |
| `properties` | array of property | No | Extension properties (CycloneDX convention) |

Each dataflow entry SHALL include a `bom-ref`. The `bom-ref` SHALL
be unique within the BOM document. Edge identity enables
annotations, policy findings, suppressions, threat-model findings,
and other downstream records to reference a specific dataflow edge.
CycloneDX 1.7 governance features key off `bom-ref`; without stable
edge identifiers, downstream tooling must invent synthetic IDs.

### 6.4 Operation Types

Dataflows are unidirectional. The `source` and `target` fields
SHALL always define the direction of actual data movement — data
flows from `source` to `target`, never the reverse. Operations
SHALL NOT determine, reverse, or override edge direction.

Dataflows MAY carry an `operations` field specifying one or more
operation types that annotate the interaction context:

| Operation | Semantics |
|-----------|-----------|
| `read` | Read/access interaction: request material or returned content |
| `write` | Create, update, append, overwrite, or store interaction: content or result |
| `execute` | Causes the target node to perform an action or side-effect |
| `delete` | Deletion interaction: request, target identifier, instruction, or result |

Operations describe *what kind of interaction* the data movement
represents, not *which way* data moves. Edge direction and
operation type are independent. The `write` operation intentionally
covers create, update, append, overwrite, and store. Producers that
need finer mutation semantics SHOULD use `properties[]` or a future
profile instead of expanding the core operation vocabulary.

**Request-response patterns:**

Interactions that involve data moving in both directions (such as
querying a database or calling an API) SHALL be represented as two
separate unidirectional edges. Each edge represents one direction
of data movement and carries its own operations:

```json
[
  {
    "bom-ref": "df-kb-query",
    "source": "kb-retriever",
    "target": "knowledge-base",
    "operations": ["read"],
    "name": "Query request"
  },
  {
    "bom-ref": "df-kb-result",
    "source": "knowledge-base",
    "target": "kb-retriever",
    "operations": ["read"],
    "dataRef": "data-kb-pifi-outbound",
    "name": "Query results"
  }
]
```

The first edge carries the query payload from the retriever to the
knowledge base. The second edge carries the read results back. Both
are annotated `read` because both are part of a read interaction.
A consuming tool can follow edges in `source` → `target` direction
to trace data movement without applying reversal rules.

Similarly, an API call that sends data and triggers processing is
two edges:

```json
[
  {
    "bom-ref": "df-email-request",
    "source": "email-agent",
    "target": "sendgrid-api",
    "operations": ["write", "execute"],
    "name": "Send email request"
  },
  {
    "bom-ref": "df-email-response",
    "source": "sendgrid-api",
    "target": "email-agent",
    "name": "Delivery confirmation"
  }
]
```

The request edge carries `execute` because it causes the target API to
perform a side-effect. The response edge carries no `execute`
operation because the confirmation is returned data; it does not
itself cause the agent to perform a side-effect.

**Dataflows without operations:**

A dataflow entry without an `operations` field represents
directional data movement with no further semantic annotation.
This is the typical case for edges between processing components
within the pipeline:

```json
{
  "bom-ref": "df-filter-to-llm",
  "source": "input-filter",
  "target": "claude-sonnet"
}
```

This states: data moves from the input filter to the LLM.

**Operation classification:**

Operations fall into two categories:

- *Transfer operations* (`read`, `write`) describe payload
  movement — what data is being delivered from source to target.
- *Invocation operations* (`execute`, `delete`) describe state
  mutation or external compute caused at the target by the data
  movement.

These categories are not mutually exclusive. In modern AI systems,
moving data and triggering actions are often the same network
request. An agent calling an email API sends a payload (the
recipient list and message body) and triggers a side-effect (the
emails are sent). The transfer and invocation are inseparable — a
single HTTP POST both delivers the data and fires the action.

**Multiple operations on a single edge:**

A dataflow MAY contain multiple operations only when all listed
operations apply to the same directional data movement from source
to target and the same payload. Producers SHOULD use separate
dataflow entries when operations involve different payloads,
classifications, or effects.

Combining a transfer operation with an invocation operation on the
same edge is the most common multi-operation pattern. It states
that the data movement both delivers a payload *and* triggers
compute or a side-effect at the target:

```json
{
  "bom-ref": "df-send-emails",
  "source": "email-agent",
  "target": "sendgrid-api",
  "operations": ["write", "execute"],
  "dataRef": "data-user-email-addresses",
  "name": "Send emails to generated recipient list"
}
```

The `write` indicates the payload (email addresses and message
body) is delivered to the service. The `execute` indicates the
service performs active processing — sending the emails — rather
than passively storing the data. Neither operation alone captures
the full semantics; the combination does.

**`execute` and `delete` semantics:**

`execute` indicates that the data movement is associated with
invocation of functionality or a side-effect at the target. Response
data SHOULD be represented as a separate reverse dataflow and SHOULD
NOT carry `execute` unless that response data itself causes a
side-effect at its target.

`delete` indicates that the data movement is associated with a
deletion request, deletion instruction, or deletion result. The
deleted data object SHOULD be identified by `dataRef`, `target`,
or `properties`.

### 6.5 Data References

A dataflow MAY reference a specific data descriptor using the
`dataRef` field. `dataRef` describes the payload on the edge, not an
endpoint-local storage record. This connects the structural dataflow
edge to data classification and governance information without
duplicating it on the edge.

`dataRef` MAY refer to a referenceable data descriptor owned by either
endpoint, including `service.data[]` entries and component data
descriptors, provided the referenced object has a unique `bom-ref`.
The endpoint-owned descriptor is reused as metadata for the edge
payload.

CycloneDX services support `data[]` entries specifying flow
direction, classification, governance, and endpoints. CycloneDX
components of type `data` and `machine-learning-model` also support
dataset-style metadata with classification and governance. A single
node may have multiple data descriptors with identical
classifications.

To prevent ambiguity, `dataRef` SHALL NOT rely on classification
strings. When `dataRef` is used, the referenced data descriptor
MUST include a unique `bom-ref` identifier, and the `dataRef` value
MUST match that identifier.

> **Note:** The CycloneDX `serviceData` type does not currently
> define a `bom-ref` field. This specification proposes adding an
> optional `bom-ref` to `serviceData` entries to support
> unambiguous data references.

This exact matching allows consuming tools to deterministically
associate dataflow edges with specific data payloads, preventing
collisions when a node handles complex or overlapping
classifications.

If source and target define different descriptors for the same
real-world data, the producer SHOULD reference the descriptor that
best describes the payload while it moves on that edge. If neither
endpoint descriptor accurately describes the edge payload, the
producer SHOULD omit `dataRef` and encode edge-specific
classification or governance details in `properties[]` until
edge-scoped data descriptors are defined.

When `dataRef` references a `service.data[]` entry, the
`serviceData.flow` value SHOULD be consistent with the dataflow
edge direction relative to the service that owns the descriptor. If
the descriptor is owned by the source service, `flow` SHOULD be
`outbound` or `bi-directional`. If the descriptor is owned by the
target service, `flow` SHOULD be `inbound` or `bi-directional`. If
direction is unknown, `flow` MAY be `unknown`.

Endpoint-relative flow values on different endpoint descriptors do
not need to match. For example, the source service may describe a
payload as `outbound` while the target service describes the same
payload as `inbound`. Producers that need to preserve both endpoint
views SHOULD use two descriptors or edge properties rather than
overloading a single `dataRef`.

**Example:**

```json
{
  "services": [
    {
      "bom-ref": "customer-db",
      "name": "Customer Database",
      "trustZone": "internal-vpc",
      "data": [
        {
          "bom-ref": "data-customer-pii-outbound",
          "classification": "PII",
          "flow": "outbound",
          "destination": [
            "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#data-processor"
          ]
        },
        {
          "bom-ref": "data-system-telemetry-outbound",
          "classification": "Public",
          "flow": "outbound"
        }
      ]
    }
  ],
  "dataFlows": [
    {
      "bom-ref": "df-read-pii",
      "source": "customer-db",
      "target": "data-processor",
      "operations": ["read"],
      "dataRef": "data-customer-pii-outbound"
    }
  ]
}
```

### 6.6 Distinguishing Dataflows from Dependencies

The `dataFlows[]` array is semantically distinct from the CycloneDX
`dependencies[]` array:

| Aspect | `dependencies[]` | `dataFlows[]` |
|--------|-------------------|---------------|
| Semantics | "A depends on B" (build/runtime) | "Data moves from A to B" |
| Direction | Dependency direction | Data movement direction |
| Operation types | Not applicable | Optional (`read`, `write`, `execute`, `delete`) |
| Typical use | Software supply chain | System runtime topology |

A BOM document MAY include both `dependencies[]` and `dataFlows[]`.
They describe different relationships and are not redundant.

### 6.7 Native XML Encoding

Native CycloneDX 1.8 XML encodes trust zones and dataflows using the
same plural-container/singular-entry pattern used elsewhere in
CycloneDX. A dataflow `bom-ref` is an XML attribute, matching the
CycloneDX convention for referenceable elements.

This is intentionally asymmetric with JSON: JSON represents `bom-ref`
as an object property, while XML represents `bom-ref` as an attribute.
That mirrors existing CycloneDX JSON and XML encoding conventions for
referenceable elements.

```xml
<trustZones>
  <trustZone default="true">
    <name>internal-vpc</name>
    <description>Private cloud network</description>
  </trustZone>
</trustZones>

<dataFlows>
  <dataFlow bom-ref="df-1">
    <source>user-input</source>
    <target>input-filter</target>
    <operations>
      <operation>read</operation>
    </operations>
    <dataRef>data-user-pii-outbound</dataRef>
    <name>User message to input filter</name>
  </dataFlow>
</dataFlows>
```

The root `bom` XML sequence SHOULD place system structure fields
immediately after the graph node collections:

```text
metadata
components
services
trustZones
dataFlows
externalReferences
dependencies
...
```

This keeps the environmental and edge metadata adjacent to the
component and service nodes they describe while preserving the
existing meaning of `dependencies[]`.

Because CycloneDX XML schemas enforce element order, this sequence is
a schema requirement, not only a documentation convention. Native XML
adoption requires the CycloneDX XSD to add `trustZones` and
`dataFlows` at the selected location in the root `bom` sequence.

## 7. System Identity and Lifecycle

### 7.1 System Identity

The BOM `metadata.component` SHALL identify the system as a whole:

```json
{
  "metadata": {
    "component": {
      "bom-ref": "rag-support-agent",
      "type": "application",
      "name": "RAG Customer Support Agent",
      "version": "1.0.0"
    }
  }
}
```

### 7.2 Lifecycle Phase

The `metadata.lifecycles[]` array SHOULD include an entry indicating
the lifecycle phase the structure represents. AIBOM documents use the
standard CycloneDX lifecycle values. The most common topology phases
are:

- `design`: Architectural intent — what the system is designed to be.
- `operations`: Deployed runtime topology — what the system currently
  is.

Other CycloneDX lifecycle values MAY be used when they describe the
graph state more accurately. For example, a training pipeline before a
model artifact exists may be `build`, a graph captured immediately
after model creation may be `post-build`, inventory-only discovery may
be `discovery`, and model retirement may be `decommission`.

```json
{
  "metadata": {
    "lifecycles": [{ "phase": "operations" }]
  }
}
```

### 7.3 Topology Interpretation

Agentic systems have dynamic structure: an orchestrator may invoke
different tools depending on context. The system structure graph
could theoretically represent any of three interpretations:

- **Declared topology:** The tools, services, and data assets the
  agent is *configured* to access — the allowed tool list, the
  orchestrator config, the granted permissions.
- **Maximum topology:** All tools the agent *could* invoke, including
  every capability in the underlying framework's dependency tree.
- **Observed topology:** The tools and paths actually invoked in a
  specific execution trace.

A conforming document SHALL represent the **declared topology**
unless it explicitly identifies an alternative interpretation in
its BOM-level properties. Declared topology maps the governed, instantiated
state of the system — the configuration that was built and deployed.

This default is normative for the following reasons:

- Configuration is architecture in agentic systems. The declarative
  setup (allowed tool list, system prompt, orchestrator config)
  defines the system boundaries. Maximum topology tends to map raw
  software materials, which belong in `dependencies[]` when they are
  software dependency relationships.
- Policy enforcement requires intent. Automated compliance
  evaluation must reflect what was shipped, not what the underlying
  libraries are theoretically capable of. A maximum topology graph
  would cause every agent to fail a "no database write access"
  audit simply because a write tool exists in the framework.
- False positives destroy utility. Modern agent frameworks ship
  with large tool libraries. Mapping every possible tool as an
  edge drowns the risk signal in noise.

For example, consider an agent framework configured with one allowed
tool: `search`. The framework package may also contain a `python_exec`
tool, database tools, or other optional capabilities. In declared
topology, the AIBOM includes the configured `search` tool and omits
`python_exec` because it is not part of the deployed agent
configuration. In maximum topology, a producer MAY include
`python_exec` and other available framework capabilities if the
document is intentionally mapping the framework's possible capability
surface. In observed topology, `python_exec` appears only if it was
actually invoked in the captured execution trace.

Producers that generate maximum or observed topology documents
SHOULD declare the interpretation using a BOM-level property:

```json
{
  "properties": [
    {
      "name": "aibom:topologyInterpretation",
      "value": "maximum"
    }
  ]
}
```

Valid values are `declared` (the default, need not be stated),
`maximum`, and `observed`. Consumers encountering a document
without this property SHALL assume declared topology.

### 7.4 Tenant Scope

An AIBOM describes a system, deployment, or release topology. It does
not describe individual tenant data instances by default.

If multiple tenants share the same topology, producers SHOULD emit one
AIBOM for the shared system or deployment. If tenants have materially
different models, data stores, processors, trust zones, geographic
regions, or data handling obligations, producers SHOULD emit separate
deployment-scoped or tenant-scoped BOMs. Producers SHOULD NOT emit one
AIBOM per user or tenant unless the graph structure or governance
context materially differs.

## 8. Complete Example

The following example describes a RAG-based customer support agent
with an input guardrail, an LLM, a knowledge base retriever, a
local embeddings index (a data component), and an output PII filter.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.8",
  "serialNumber": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "version": 1,
  "properties": [
    { "name": "aibom:specVersion", "value": "0.1-draft" },
    { "name": "aibom:encoding", "value": "native" },
    { "name": "aibom:profile", "value": "full" }
  ],
  "metadata": {
    "timestamp": "2026-05-18T00:00:00Z",
    "lifecycles": [{ "phase": "operations" }],
    "component": {
      "bom-ref": "rag-support-agent",
      "type": "application",
      "name": "RAG Customer Support Agent",
      "version": "1.0.0"
    }
  },

  "components": [
    {
      "bom-ref": "input-filter",
      "type": "application",
      "name": "Input Safety Filter",
      "purl": "pkg:generic/acme.com/input-filter@1.2.0"
    },
    {
      "bom-ref": "claude-sonnet",
      "type": "machine-learning-model",
      "name": "Claude Sonnet",
      "purl": "pkg:generic/anthropic.com/claude-sonnet@4.5",
      "trustZone": "public-internet"
    },
    {
      "bom-ref": "kb-retriever",
      "type": "application",
      "name": "Knowledge Base Retriever",
      "purl": "pkg:generic/acme.com/kb-retriever@2.1.0"
    },
    {
      "bom-ref": "pii-filter",
      "type": "application",
      "name": "Output PII Filter",
      "purl": "pkg:generic/acme.com/pii-filter@1.0.3"
    },
    {
      "bom-ref": "support-embeddings",
      "type": "data",
      "name": "Support Article Embeddings",
      "purl": "pkg:generic/acme.com/support-embeddings@2026.05",
      "description": "Pre-computed embeddings for customer support knowledge base articles"
    }
  ],

  "services": [
    {
      "bom-ref": "user-input",
      "name": "User Input Channel",
      "endpoints": ["https://support.example.com/chat"],
      "x-trust-boundary": true,
      "trustZone": "public-internet",
      "data": [
        {
          "bom-ref": "data-user-pii-outbound",
          "classification": "PII",
          "flow": "outbound"
        }
      ]
    },
    {
      "bom-ref": "knowledge-base",
      "name": "Customer Knowledge Base",
      "endpoints": ["https://kb.internal:6333"],
      "trustZone": "internal-vpc",
      "data": [
        {
          "bom-ref": "data-kb-pifi-outbound",
          "classification": "PIFI",
          "flow": "outbound"
        }
      ]
    },
    {
      "bom-ref": "user-output",
      "name": "User Response Channel",
      "endpoints": ["https://support.example.com/chat"],
      "x-trust-boundary": true,
      "trustZone": "public-internet"
    }
  ],

  "trustZones": [
    {
      "name": "public-internet",
      "description": "Untrusted external network"
    },
    {
      "name": "internal-vpc",
      "description": "Private cloud network",
      "default": true
    }
  ],

  "dataFlows": [
    {
      "bom-ref": "df-userinput-to-filter",
      "source": "user-input",
      "target": "input-filter",
      "operations": ["read"],
      "dataRef": "data-user-pii-outbound",
      "name": "User message to input filter"
    },
    {
      "bom-ref": "df-filter-to-llm",
      "source": "input-filter",
      "target": "claude-sonnet",
      "name": "Filtered input to LLM"
    },
    {
      "bom-ref": "df-llm-to-retriever",
      "source": "claude-sonnet",
      "target": "kb-retriever",
      "name": "Retrieval request"
    },
    {
      "bom-ref": "df-kb-query",
      "source": "kb-retriever",
      "target": "knowledge-base",
      "operations": ["read"],
      "name": "Knowledge base query"
    },
    {
      "bom-ref": "df-kb-result",
      "source": "knowledge-base",
      "target": "kb-retriever",
      "operations": ["read"],
      "dataRef": "data-kb-pifi-outbound",
      "name": "Knowledge base results"
    },
    {
      "bom-ref": "df-embeddings-read",
      "source": "support-embeddings",
      "target": "kb-retriever",
      "operations": ["read"],
      "name": "Embeddings for similarity search"
    },
    {
      "bom-ref": "df-retriever-to-llm",
      "source": "kb-retriever",
      "target": "claude-sonnet",
      "name": "Retrieved context"
    },
    {
      "bom-ref": "df-llm-to-piifilter",
      "source": "claude-sonnet",
      "target": "pii-filter",
      "name": "Raw LLM response"
    },
    {
      "bom-ref": "df-piifilter-to-output",
      "source": "pii-filter",
      "target": "user-output",
      "operations": ["write"],
      "name": "Filtered response to user"
    }
  ]
}
```

### 8.1 Reading the Example

Every edge in `dataFlows[]` points in the direction data actually
moves — `source` → `target` is always the data movement direction.
A consumer can follow edges to trace data paths without reversal
rules.

**Ingress:** User input arrives at the user-input channel and flows
to the input filter (`df-userinput-to-filter`, operation: `read`).
The `dataRef` links to the `data-user-pii-outbound` data entry on
the service, identifying this as PII-classified data.

**Processing pipeline:** The input filter sends filtered data to
the LLM (`df-filter-to-llm`). The LLM sends a retrieval request
to the knowledge base retriever (`df-llm-to-retriever`). These
component-to-component edges carry no operations — both endpoints
are processing components.

**Knowledge base interaction:** The retriever's interaction with
the knowledge base is two edges: the query (`df-kb-query`, data
moves from retriever to KB) and the results (`df-kb-result`, data
moves from KB back to retriever). Both carry operation `read`. The
results edge has a `dataRef` linking to the PIFI-classified data
on the KB service. The retriever also reads from the local
embeddings index (`df-embeddings-read`), a data component.

**Egress:** The retriever sends context to the LLM
(`df-retriever-to-llm`), the LLM responds to the PII filter
(`df-llm-to-piifilter`), and the PII filter writes the filtered
response to the user output channel (`df-piifilter-to-output`,
operation: `write`).

**Trust zones** provide environmental context. The Claude Sonnet
component and the user-facing channels explicitly declare
`"trustZone": "public-internet"`. The remaining components inherit
`"internal-vpc"` from the trust zone entry marked `"default": true`.
A consuming tool can detect every trust boundary crossing by comparing
the trust zones of `source` and `target` on each edge — for example,
`df-filter-to-llm` crosses from `internal-vpc` to
`public-internet`, and `df-llm-to-piifilter` crosses back.

**Graph queries:** Because edges are true dataflow, standard graph
traversal works directly. "What data can reach the LLM?" — follow
all edges where the LLM is the target. "What PII-classified data
leaves the system?" — find edges with `dataRef` pointing to
PII-classified descriptors and trace forward to egress. "Does
unredacted PII reach the output?" — trace from the PII-bearing
ingress edge through the graph to the egress edge.

## 9. Relationship to CycloneDX Primitives

### 9.1 Element Mapping

| This Specification | CycloneDX Element | Status |
|--------------------|-------------------|--------|
| Components (active and passive nodes) | `components[]` | Existing — no change (includes type `data`) |
| Component trust zone | `component.trustZone` | **Proposed addition — optional** (mirrors `service.trustZone`) |
| Services (runtime resources/interfaces) | `services[]` | Existing — SaaSBOM conventions |
| Service data classification | `service.data[]` | Existing — proposes optional `bom-ref` on `serviceData` |
| Service trust zone label | `service.trustZone` | Existing — no change |
| Service trust boundary flag | `service.x-trust-boundary` | Existing — no change |
| Trust zone definitions | `trustZones[]` | **Proposed addition — optional** |
| Default trust zone | `trustZones[].default` | **Proposed addition — optional** |
| Dataflows | `dataFlows[]` | **Proposed addition** |
| System identity | `metadata.component` | Existing — no change |
| Lifecycle phase | `metadata.lifecycles[]` | Existing — no change |

### 9.2 SaaSBOM Alignment

This specification builds on the SaaSBOM capability
(https://cyclonedx.org/capabilities/saasbom/) which defines:

- `services[]` with `endpoints`, `authenticated`, `x-trust-boundary`,
  `trustZone`, and nested `services[]` for hierarchical composition
- `service.data[]` with `flow` (inbound/outbound/bi-directional),
  `classification`, `governance`, `source`, and `destination`
- Service entries in `dependencies[]` for dependency relationships

The `dataFlows[]` array complements SaaSBOM by adding explicit
directed edges with operation semantics. SaaSBOM's `data[]` entries
on services describe what data a service handles; `dataFlows[]`
describes how that data moves through the system graph.

### 9.3 ML-BOM Alignment

CycloneDX ML-BOM (https://cyclonedx.org/capabilities/mlbom/)
defines properties on components relevant to machine learning:

- Components of type `machine-learning-model` may include a
  `modelCard` with model parameters, performance metrics, and
  ethical considerations.
- Components of type `data` may include a `data` property
  describing datasets with their type (`dataset`, `source-code`,
  `configuration`, etc.), contents, classification, and governance.

This specification uses both component types as nodes in the system
structure graph but does not redefine or extend their metadata. The
division of responsibility is:

- **ML-BOM** describes what a model or dataset *is*: its
  architecture, parameters, training provenance, performance
  metrics, ethical considerations, and dataset contents. The
  `modelCard` on a `machine-learning-model` component may reference
  the datasets used for training — this is a provenance
  relationship ("trained on dataset X") captured as static metadata.

- **This specification** describes how those elements are
  *connected* by data movement at runtime or design time. A
  dataflow edge from a training job to a model artifact
  (`"operations": ["write"]`) expresses a topological relationship
  ("the trainer writes to the model") rather than a provenance
  claim.

These views are complementary, not competing. A single model
component can carry a full `modelCard` with ML-BOM provenance
metadata *and* participate in the dataflow graph as an active node
(at inference time) or as a passive write target (at training
time). A dataset component can carry ML-BOM dataset metadata *and*
appear as a passive node that is read by a retriever or written to
by a data pipeline.

This specification does not replace ML-BOM's provenance semantics.
Producers that need both provenance and topology SHOULD use ML-BOM
metadata on components and dataflow edges between them — the two
mechanisms layer without conflict.

**Example: Training pipeline topology vs. ML-BOM provenance**

Consider a fine-tuning pipeline that takes raw customer
conversations, redacts PII, and produces a fine-tuned model.
ML-BOM can record that the resulting model was trained on the
redacted dataset — but it cannot express the intermediate
processing steps, the data movement through the redaction stage,
or the fact that raw PII-bearing data never reaches the trainer.

```json
{
  "components": [
    {
      "bom-ref": "raw-conversations",
      "type": "data",
      "name": "Raw Customer Conversations",
      "purl": "pkg:generic/acme.com/raw-conversations@2026.04",
      "description": "Unredacted support transcripts"
    },
    {
      "bom-ref": "pii-redactor",
      "type": "application",
      "name": "PII Redaction Pipeline",
      "purl": "pkg:generic/acme.com/pii-redactor@2.0"
    },
    {
      "bom-ref": "redacted-conversations",
      "type": "data",
      "name": "Redacted Customer Conversations",
      "purl": "pkg:generic/acme.com/redacted-conversations@2026.04",
      "description": "PII-free training corpus"
    },
    {
      "bom-ref": "fine-tuner",
      "type": "application",
      "name": "Model Fine-Tuning Job",
      "purl": "pkg:generic/acme.com/fine-tuner@1.3"
    },
    {
      "bom-ref": "support-model",
      "type": "machine-learning-model",
      "name": "Fine-Tuned Support Model",
      "purl": "pkg:generic/acme.com/support-model@2026.05"
    }
  ],
  "dataFlows": [
    {
      "bom-ref": "df-raw-to-redactor",
      "source": "raw-conversations",
      "target": "pii-redactor",
      "operations": ["read"],
      "name": "Raw transcripts to redactor"
    },
    {
      "bom-ref": "df-redactor-to-corpus",
      "source": "pii-redactor",
      "target": "redacted-conversations",
      "operations": ["write"],
      "name": "Redacted corpus written"
    },
    {
      "bom-ref": "df-corpus-to-trainer",
      "source": "redacted-conversations",
      "target": "fine-tuner",
      "operations": ["read"],
      "name": "Training data to fine-tuner"
    },
    {
      "bom-ref": "df-trainer-to-model",
      "source": "fine-tuner",
      "target": "support-model",
      "operations": ["write"],
      "name": "Trained model weights written"
    }
  ]
}
```

The ML-BOM `modelCard` on the fine-tuned model would record that
it was trained on `redacted-conversations` — the provenance fact.
The dataflow graph above captures what ML-BOM cannot: that raw
data passed through a PII redaction stage before reaching the
trainer, that the redactor reads PII-bearing data but the trainer
does not, and that the model artifact is the terminal write target
of the pipeline. A consuming tool can trace that raw PII-bearing data passed through
a declared redaction stage before reaching the trainer.
Verification that PII was actually removed depends on the
classification, evidence, claims, or governance metadata associated
with the redacted dataset or redaction process — information that
is invisible in the ML-BOM provenance metadata alone but that the
dataflow graph makes structurally auditable.

### 9.4 SPDX 3.0

SPDX 3.0's element-relationship model can represent related
concepts, but this specification does not claim a one-to-one
mapping to native SPDX 3.0.1 relationship types. A future mapping
should be defined separately, likely using SPDX extension
mechanisms or combinations of `hasInput`, `hasOutput`,
`hasDataFile`, `invokedBy`, `trainedOn`, `usesTool`, and
`dependsOn`.

## 10. Schema Summary

### 10.1 `dataFlows[]` Entry

```
dataFlow {
  bom-ref:      refType (REQUIRED — unique identifier for this edge)
  source:       refLinkType (reference to bom-ref in this BOM, REQUIRED)
  target:       refLinkType (reference to bom-ref in this BOM, REQUIRED)
  operations:   array of enum [read, write, execute, delete] (OPTIONAL)
  dataRef:      refLinkType (OPTIONAL — bom-ref of a descriptor for the edge payload)
  name:         string (OPTIONAL)
  description:  string (OPTIONAL)
  properties:   array of property (OPTIONAL — CycloneDX convention)
}
```

`source` → `target` SHALL always be the direction of data movement.
Operations annotate interaction context but SHALL NOT reverse or
override edge direction.

### 10.2 `trustZones[]` Entry

```
trustZone {
  name:         string (REQUIRED)
  description:  string (OPTIONAL)
  default:      boolean (OPTIONAL — at most one true value per BOM)
}
```

### 10.3 Operation Type Enum

```
operation: enum {
  read      — Part of a read/access interaction (request material or returned content)
  write     — Part of create/update/append/overwrite/store interaction
  execute   — Causes the target to perform an action or side-effect
  delete    — Part of a deletion interaction (deletion request, identifier, or result)
}
```

Operations annotate the kind of interaction or target-side effect;
they never imply or reverse data-movement direction. They SHALL NOT
determine, reverse, or override the `source` → `target` data movement
direction.

### 10.4 Semantic Validation

JSON Schema and XSD validation check document shape. AIBOM-aware
semantic validation checks graph consistency that schemas cannot fully
express. This specification defines severity classes but does not
define a validator error-code API.

| Condition | Severity |
|-----------|----------|
| `source` or `target` does not resolve by §4.3 | Error |
| `dataRef` does not resolve to a referenceable data descriptor | Error |
| operation value is not in the operation enum | Error |
| more than one trust zone has `default` set to `true` | Error |
| node `trustZone` value does not match `trustZones[]` definitions | Warning |
| `serviceData.flow` is inconsistent with the referenced service role | Warning |
| declared profile is lower than the fields intentionally emitted | Warning |
| `aibom:specVersion` is absent | Info |
| `aibom:profile` is absent and must be inferred | Info |

Producers SHOULD treat semantic errors as defects in the emitted BOM.
Producers SHOULD review warnings and either correct the document or
document why the mismatch is intentional. Consumers MAY apply stricter
local policy, but SHOULD NOT treat warning-level conditions as schema
validation failures by default.

## 11. Questions Considered

### 11.1 `dataRef` Mechanism

**Issue:** How should a dataflow edge reference a specific data
descriptor on a node? Referencing by classification string is
ambiguous when a node has multiple data entries with the same
classification. Referencing by array index is unambiguous but
fragile across edits.

**Resolution:** `dataRef` uses `bom-ref` matching and describes the
payload on the edge. This specification proposes adding an optional
`bom-ref` field to CycloneDX `serviceData` entries. The `dataRef`
value on a dataflow SHALL match the `bom-ref` of a data descriptor
owned by either endpoint.

If both endpoints have descriptors for the same real-world data,
the producer selects the descriptor that best describes the payload
while it moves on that edge. Endpoint-relative flow values are
checked relative to the service that owns the referenced descriptor:
source-owned service data should be `outbound` or `bi-directional`,
and target-owned service data should be `inbound` or
`bi-directional`. Opposite source and target flow labels are not a
conflict. See §6.5.

### 11.2 Agentic System Topology

**Issue:** Agentic systems have dynamic structure. A system graph
could represent the maximum topology (all tools the agent could
invoke), the observed topology (tools invoked in a specific
execution), or the declared topology (tools the agent is configured
to access). Leaving the interpretation unspecified destroys
comparability — consumers cannot safely merge or evaluate documents
produced under different interpretations.

**Resolution:** Declared topology is the normative default.
Configuration is architecture in agentic systems; the declarative
setup defines the system boundaries. Maximum topology tends to map raw
software materials, which belong in `dependencies[]` when they are
software dependency relationships. Producers generating alternative
interpretations declare them via a BOM-level property. See §7.3.

### 11.3 Edge Direction and Operation Semantics

**Issue:** An earlier draft encoded `source` → `target` as the
interaction direction (actor acts on resource) rather than the data
movement direction. This created two competing direction systems:
the edge direction and the operation's implied data flow direction.
A `read` edge encoded as `component → service` implied data moved
the opposite way, making graph traversal ambiguous.

**Resolution:** Edges are unidirectional. `source` → `target`
SHALL always be the direction of actual data movement. Operations
are semantic annotations that SHALL NOT determine, reverse, or
override edge direction. `execute` is target-effecting: it means the
data movement causes the target node to perform an action or
side-effect. Request-response interactions use two separate edges,
each representing one direction of data movement. See §6.4.

### 11.4 Operation Vocabulary

**Issue:** Is the current set (`read`, `write`, `execute`,
`delete`) sufficient for AI system interactions?

**Status: Deferred to v0.2.** The four operations cover common patterns.
`grant` (access delegation) was considered and excluded because the
current operation vocabulary classifies data movement caused by data
interactions, not changes to authorization state. Token issuance, ACL
exports, and permission metadata MAY still be represented as
dataflows. The special meaning "this changes who may access what" is
reserved for a future authorization or control profile. Additional
operations may be proposed as implementation experience accumulates.

### 11.5 Control Nodes

**Issue:** Some system elements are "off-path" — they do not
participate in the primary data flow but can gate, audit, or
control flows. Examples include authentication services, SIEM
systems, and observability platforms.

**Status: Deferred to v0.2.** Control node semantics are reserved for
a future extension. The current specification can represent control
nodes as components with dataflow connections, but does not define
special semantics for off-path control relationships.

### 11.6 Trust Zone Promotion

**Issue:** The current `trustZones[]` array is minimal (name and
description only). Should trust zones be promoted to fuller
entities with `bom-ref` identifiers, enabling them to participate
in dataflow graphs directly?

**Status: Deferred to v0.2.** Future versions may promote trust zones
to first-class referable entities — for example, representing data
movement to or from "the Internet" as a direct statement rather than
through an intermediary service node.

### 11.7 Hosted Model Identity

**Issue:** A hosted LLM (e.g., Claude accessed via the Anthropic
API) has dual identity: the model artifact and the API service
endpoint. The current examples model hosted LLMs as components
with a `trustZone`, but the runtime endpoint is arguably a service
with its own authentication, data handling, and trust boundary
characteristics.

**Resolution:** Hosted model identity is represented as a component
by default. A hosted model is a model or capability participating in
the AI system, not necessarily the provider resource that exposes an
endpoint. A separate service MAY be added when the API endpoint,
authentication boundary, provider resource, or data handling behavior
is material to the analysis.

When both are represented, the service represents the endpoint or
provider resource, not the hosted model itself. The service MAY
reference the model component using an AIBOM property until a native
relationship is defined:

```json
{
  "bom-ref": "anthropic-messages-api",
  "name": "Anthropic Messages API",
  "endpoints": ["https://api.anthropic.com/v1/messages"],
  "trustZone": "public-internet",
  "properties": [
    { "name": "aibom:modelRef", "value": "claude-sonnet" }
  ]
}
```

Producers SHOULD NOT use `dependencies[]` to express this hosted
model relationship. `dependencies[]` retains its CycloneDX meaning:
software supply-chain and dependency relationships, not runtime
service-to-model binding.

### 11.8 Alignment with CycloneDX v2.0

**Issue:** CycloneDX v2.0 (Transparency Exchange Language) includes
"architectural blueprints" in its stated scope. The Blueprints
Feature Working Group has proposed Architectural Bill of Materials
(ABOM) and Bill of Behaviors (BOB) concepts, though no
specification has been released.

**Status: Depends on external CycloneDX work.** If v2.0 defines native
graph structure representation, this specification should map onto it.
If that scope remains undefined, this specification provides a
concrete starting point grounded in existing CycloneDX primitives.

## 12. Security Considerations

AIBOM documents describe system topology, trust boundaries, data
classifications, and AI processing paths. This information can be
sensitive. Producers SHOULD treat AIBOMs as security-relevant
artifacts and SHOULD classify, redact, and distribute them according
to the sensitivity of the system they describe.

Producers SHOULD NOT assume that an externally shareable AIBOM can
contain the same detail as an internal AIBOM. Public or customer-facing
AIBOMs may need to omit or generalize internal hostnames, private
network names, exact control points, sensitive data stores, tenant
identifiers, prompts, model deployment names, and operational
detection paths. If details are omitted, producers SHOULD prefer
explicit redaction or abstraction over silently emitting an incomplete
graph that appears authoritative.

Trust zone labels and dataflow edges are producer assertions. A
malicious or careless producer can mislabel a public resource as
internal, omit sensitive flows, or describe intended architecture
rather than deployed reality. Consumers SHOULD treat AIBOM claims as
untrusted input unless they are tied to a trusted producer, signature,
attestation, audit evidence, or other provenance mechanism.

Consumers SHOULD validate graph consistency before using an AIBOM for
policy decisions. Unresolved nodes, duplicate defaults, unknown trust
zones, or inconsistent flow metadata can cause false assurance or
misleading risk analysis. Consumers SHOULD distinguish schema-valid
documents from semantically trustworthy documents.

AIBOMs may reveal attack paths. In particular, dataflows can expose
where PII enters and leaves a system, which services can trigger
side-effects, which components process model inputs, and where trust
boundaries are crossed. Organizations SHOULD define separate handling
rules for internal, partner, regulator, and public AIBOMs.

## Appendix A. Future PURL Type Note (Non-Normative)

The Package URL community is discussing identifiers for software
outside package registries, including commercial, proprietary,
internal, standalone, and binary-only software. If a future PURL type
for this use case is registered, AIBOM producers may use it like any
other valid PURL. This specification does not depend on that work and
does not define any AIBOM-specific substitute PURL field.

## Appendix B. CycloneDX 1.7 Compatibility Encoding (Non-Normative)

The proposed fields in this specification (`dataFlows[]`,
`trustZones[]`, `trustZone` on components, `trustZones[].default`,
`bom-ref` on `serviceData`) are not valid against the unmodified
CycloneDX 1.7 JSON schema. Implementers that need valid 1.7
documents before schema adoption MAY encode dataflow information
using BOM-level CycloneDX `properties[]`.

The following encoding represents one dataflow edge using
BOM-level properties with a namespaced key convention:

```json
{
  "properties": [
    { "name": "aibom:specVersion", "value": "0.1-draft" },
    { "name": "aibom:encoding", "value": "properties" },
    { "name": "aibom:profile", "value": "classified" },
    { "name": "aibom:dataFlow:df-1:source", "value": "user-input" },
    { "name": "aibom:dataFlow:df-1:target", "value": "input-filter" },
    { "name": "aibom:dataFlow:df-1:operation", "value": "read" },
    { "name": "aibom:dataFlow:df-1:dataRef", "value": "data-user-pii-outbound" }
  ]
}
```

The key pattern is `aibom:dataFlow:{edge-bom-ref}:{field}`. For
edges with multiple operations, repeat the `operation` key:

```json
[
  { "name": "aibom:dataFlow:df-send:operation", "value": "write" },
  { "name": "aibom:dataFlow:df-send:operation", "value": "execute" }
]
```

This encoding is intentionally verbose and loses the structural
benefits of a dedicated `dataFlows[]` array. It is provided as a
transitional mechanism, not a recommended long-term approach.

Because CycloneDX 1.7 `serviceData` entries do not have `bom-ref`,
compatibility-mode `dataRef` values need a property-encoded data
descriptor. Producers MAY encode such descriptors as BOM-level
properties:

```json
[
  { "name": "aibom:data:data-user-pii-outbound:owner", "value": "user-input" },
  { "name": "aibom:data:data-user-pii-outbound:ownerType", "value": "service" },
  { "name": "aibom:data:data-user-pii-outbound:classification", "value": "PII" },
  { "name": "aibom:data:data-user-pii-outbound:flow", "value": "outbound" }
]
```

The `owner` value is the `bom-ref` of the component or service that
owns the data descriptor. The `ownerType` value is `component` or
`service`.

Trust zones MAY be similarly encoded:

```json
[
  { "name": "aibom:trustZone:public-internet", "value": "Untrusted external network" },
  { "name": "aibom:trustZone:internal-vpc", "value": "Private cloud network" },
  { "name": "aibom:trustZone:internal-vpc:default", "value": "true" },
  { "name": "aibom:node:input-filter:trustZone", "value": "internal-vpc" }
]
```

## 13. References

- ECMA-427 Package URL Specification.
  https://ecma-international.org/publications-and-standards/standards/ecma-427/
- Package URL discussion: software without a package registry.
  https://github.com/package-url/purl-spec/blob/main/docs/decisions/001-PURL_type-software_without_registry.md
- CycloneDX ECMA-424 Specification, v1.7 (October 2025).
  https://github.com/CycloneDX/specification
- CycloneDX SaaSBOM Capability.
  https://cyclonedx.org/capabilities/saasbom/
- CycloneDX ML-BOM Capability.
  https://cyclonedx.org/capabilities/mlbom/
- CycloneDX Services Use Case.
  https://cyclonedx.org/use-cases/services/
- CycloneDX Specification Overview.
  https://cyclonedx.org/specification/overview/
- CycloneDX Blueprints Feature Working Group.
  https://cyclonedx.org/participate/working-groups/
- OWASP AIBOM Project.
  https://owasp.org/www-project-aibom/
- SPDX 3.0 AI BOM Implementation Guide. Linux Foundation, 2025.
  https://www.linuxfoundation.org/research/ai-bom
- EU Artificial Intelligence Act, Annex IV.
- CycloneDX Transparency Exchange API.
  https://github.com/CycloneDX/transparency-exchange-api
