# AIBOM System Structure — Working Group Circulation Proposal

**Status:** Draft proposal for OWASP AIBOM Working Group circulation
**Date:** 2026-05-21
**Decision record:** `aibom-questions-considered.md`

## Purpose

This proposal defines the AIBOM v0.1 system-structure delta. It makes AI system
structure explicit and machine-readable while keeping analysis, risk scoring,
compliance conclusions, and control sufficiency outside AIBOM Core.

AIBOM standardizes graph facts: system nodes, directed data movement, graph
self-description, model identity, system membership, trust context, and
evidence targetability. Downstream tools can use those facts for policy,
security, procurement, assurance, or operational review, but AIBOM Core does
not encode those downstream conclusions.

## Scope And Non-Goals

AIBOM v0.1 is graph-capable across scopes. When a BOM declares AI system scope
or AIBOM System Structure conformance, it is graph-bearing: it MUST include or
normatively reference system-structure graph content sufficient for the declared
scope and completeness claim. A model-only or dataset-only AIBOM can be
graph-capable without carrying a full system graph.

AIBOM Core does not define:

- risk scores;
- policy findings;
- compliance status;
- control effectiveness;
- legal responsibility;
- trustworthiness or assurance level.

The boundary is intentional. AIBOM provides the factual substrate and vocabulary
for evaluation; it does not standardize the evaluator's policy verdict.

## Proposal Summary

The v0.1 proposal consists of:

- a required Graph Self-Description block;
- directed `dataFlows[]` edges with stable target ids;
- edge-scoped payload descriptors and optional target-interaction operation
  annotations;
- edge evidence as targetable attachment, not a native edge field;
- producer-relative trust context;
- a service-first rule for provider-hosted model endpoints, with required model
  identity;
- an optional, scope-relative `aibom:systemRelationship` node property for
  system membership;
- a reserved requirement/evidence mapping convention that is evidence-targeting
  only, not a compliance profile;
- a three-layer delivery model: abstract AIBOM information model, native
  CycloneDX 1.8 target encoding, and normative CycloneDX 1.7-compatible
  `properties[]` encoding;
- two implementation tiers: AIBOM Core and AIBOM Enriched.

Stable A-numbers below are retained so issues, examples, and implementation
plans can cite exact decisions.

## Part A — System-Structure Semantics

### A1. Graph Self-Description Block — REQUIRED

An AIBOM graph SHALL carry a document-level Graph Self-Description block with
four axes:

- `graphType`;
- `generationMethod`;
- `scope`;
- `completeness`.

The `generationMethod` axis is the AIBOM document-level provenance
declaration — how the graph was produced. AIBOM defines no separate
provenance model.

In AIBOM Core, these axes are BOM-level `aibom:` properties. The
`completeness` axis is carried as `aibom:completeness`, whose values map onto
CycloneDX `aggregateType` semantics. In AIBOM Enriched, the same completeness
claim SHOULD also be expressed as `compositions[].aggregate` over the relevant
graph target set.

`complete-for-declared-scope` is not a separate aggregate value. It is
`complete` interpreted over the declared `scope` and graph target set.
Intentional redaction is represented as incompleteness plus an explanatory
AIBOM property such as `aibom:exclusionsNote`. Observed-window completeness is
an AIBOM refinement that supports inference only within the stated observation
window.

The Graph Self-Description block is the only mandatory new document-level
addition in v0.1. It does not make graph content optional: an AIBOM that
declares AI system scope or AIBOM System Structure conformance MUST include or
normatively reference graph-bearing content using the AIBOM Core or Enriched
encoding.

Stable target ids SHOULD be defined for the self-description axes, such as
`aibom:selfDescription:graphType`, so declarations and evidence can target
them.

### A2. Graph Completeness Consumer Rule

Consumers SHALL NOT interpret the absence of a `dataFlows[]` edge as evidence
that no data movement exists unless the relevant completeness claim supports
that inference for the declared `scope`, `graphType`, and graph target set.

Incomplete, redacted, or unknown graphs can support positive findings; they
cannot support negative assurance. Observed-window completeness supports
negative inference only inside the stated observation window and target set.

In AIBOM Core, unless a narrower target set is declared,
`aibom:completeness` applies to all AIBOM graph objects within the declared
`scope`, including decoded `dataFlow` edges, graph-participating nodes, and
required self-description axes. AIBOM Enriched can refine the target set with
`compositions[]`.

### A3. `dataRefs[]` Plural

A `dataFlow` edge carries plural `dataRefs[]`. Singular `dataRef` MAY be
accepted as a draft compatibility alias but should not be the preferred form.

### A4. Edge-Scoped Inline `data[]`

A `dataFlow` edge MAY carry inline `data[]` descriptors, reusing the
`serviceData` shape, when no endpoint-owned data descriptor accurately
describes the payload that moved on that edge.

### A5. Component Function Vocabulary Is Deferred

AIBOM v0.1 does not define `aiOperations[]`, `aiFunctions[]`, or a similar
node-level capability taxonomy.

The need is real, but it is outside the v0.1 system-structure floor. The v0.1
graph records which data can reach which node, service, boundary, or artifact.
It does not require producers to encode the function performed by each internal
node.

Producers that already have model-card metadata, formulation metadata, service
roles, component types, or local properties MAY include them through existing
CycloneDX mechanisms. Those labels are not AIBOM v0.1 conformance fields.

Deferred work should decide whether AI function labels belong on nodes,
services, formulation objects, interaction edges, or a separate companion
profile. The default assumption for v0.1 is that internal processing is node
behavior, not edge behavior.

### A6. Edges Must Be Referenceable

Every `dataFlow` edge SHALL be a stable, referenceable target: a `bom-ref` in
the native encoding, and the canonical decoded id defined below in the
CycloneDX 1.7 property encoding. This is a graph-structure requirement — it
is what lets AIBOM-aware declarations, requirement mappings, findings,
suppressions, and compositions attach to a specific edge.

AIBOM defines no evidence or provenance model and requires no evidence on any
edge. There is no native `dataFlow.evidence` field. Edge-level evidence MAY
be attached to the edge id through existing CycloneDX constructs —
`declarations` whose `targets` reference the edge id (AIBOM Enriched), or
`externalReferences` (AIBOM Core).

For AIBOM Core property encoding, the property group
`aibom:dataFlow:{compat-id}:*` decodes into one logical edge whose canonical
local AIBOM target id is `aibom:dataFlow:{compat-id}`. `{compat-id}` identifies
the property group; the fully qualified decoded target id is used by
AIBOM-aware declarations, requirement mappings, findings, suppressions, and
compositions.

### A7. Operations Record Target-Interaction Intent

`operations[]`, when present, record producer-declared interaction intent with
respect to the target as a resource, interface, store, actor, tool, service,
workflow, or other action-bearing endpoint.

Operations do not classify node capabilities or ordinary internal processing
behavior. Edges between internal pipeline components normally omit
`operations[]` unless the edge is intentionally modeling a read, write, delete,
or execute interaction with such a target. Internal behavior is represented by
the target node's identity and metadata, by `formulation` where process lineage
is relevant, and by downstream dataflows.

`operations[]` do not determine dataflow direction. `source -> target` always
means data moved from source to target. Request and response movements should be
represented as separate unidirectional edges when both are material.

### A8. `execute`

`execute` means the data movement records an intent to invoke target
functionality whose material effect is an action, workflow, downstream behavior,
or state transition beyond passive receipt, storage, or ordinary computation
over the received data.

`execute` SHALL NOT be used merely because a component filters, transforms,
embeds, ranks, infers, or otherwise computes over data as part of the pipeline.
AI-native computation such as inference, embedding, ranking, or evaluation is
outside the v0.1 AIBOM operation vocabulary unless represented through existing
CycloneDX component, service, model-card, formulation, or property metadata.

### A9. Active/Passive Terminology Is Non-Normative

Active/passive terminology is explanatory only. Normative behavior is
determined by incident edges and operation annotations.

### A10. `metadata.component` Participation

`metadata.component` is not an ordinary graph processing node unless the BOM
subject is itself a runtime participant. Otherwise, producers should model
runtime behavior with explicit component or service nodes.

### A11. Semantic Validation

AIBOM-aware validators SHOULD apply semantic checks, including:

- duplicate edge `bom-ref` or decoded edge target id: Error;
- empty `operations[]`: Error;
- duplicate operations: Warning;
- `dataRefs[]` descriptor unrelated to either endpoint and no inline `data[]`:
  Warning or Error;
- missing Graph Self-Description axis: Error;
- inherited or default trust zone affecting a boundary conclusion: Info or
  Warning;
- AI-system-scope graph with material external or hosted nodes and no
  `aibom:systemRelationship`: Warning.

### A12. Trust Zones

Trust zones are producer-relative, not absolute. When trust zones are used, the
BOM SHOULD declare `aibom:trustPerspective` so consumers know whose trust frame
is represented.

Trust-zone parent hierarchy is deferred to v0.2.

### A13. Compatibility-Mode Identifier Grammar

`compat-id = 1*( ALPHA / DIGIT / "." / "_" / "-" )` or percent-encoding.

### A14. ABOM / TM-BOM Relationship

AIBOM graph primitives may provide a substrate for future ABOM, BOB, or TM-BOM
mappings. Those mappings are outside v0.1 scope.

### A15. Off-Path Control Purpose — DEFERRED

Off-path control-purpose annotations, including `human-oversight`, `logging`,
`post-market-monitoring`, `cybersecurity`, `risk-control`, `audit`, and
`telemetry`, are deferred to v0.2.

### A16. Streaming

Streaming is recorded as a considered v0.1 topic. No native streaming field is
proposed in this delta.

### A17. Native Schema Issues

CycloneDX 1.8 native schema issues should be filed separately before the WG
treats native fields as accepted.

### A18. Structure, Not Analysis

AIBOM v0.1 standardizes the system-structure graph and its self-description,
not risk scoring, policy findings, compliance conclusions, or control efficacy.

### A19. Conformance Examples

The proposal should include worked examples for at least:

- an inference system with a hosted model endpoint;
- a training or fine-tuning pipeline showing the division between
  `formulation` and `dataFlows[]`.

### A20. System Membership: `aibom:systemRelationship`

AIBOM defines an optional node-level property,
`aibom:systemRelationship`, orthogonal to component versus service.

v0.1 values:

- `constituent` — intentionally part of the system described by this BOM's
  declared scope, even if operated by a third party or across a trust boundary.
- `external` — outside the described scope, represented because it sends data
  to, receives from, hosts, controls, observes, or otherwise interacts with the
  system.

Safeguards:

- **Scope-relative:** `constituent` is relative to the BOM's declared `scope`.
  The same node can be `constituent` in one BOM and `external` in another.
- **No control implication:** `constituent` does not imply ownership,
  operational control, trust, jurisdiction, or legal responsibility. Control is
  read from existing CycloneDX fields such as `service.provider` and
  `component.supplier`.
- **No evidence implication:** `constituent` asserts scope membership only. It
  is not evidence of provider-internal topology or behavior.

If absent, system membership is unspecified. Absence MUST NOT be interpreted as
`constituent`.

If an AIBOM declares AI system scope and includes material external services,
hosted model endpoints, tools, data stores, actors, or other boundary-crossing
nodes, producers SHOULD classify material graph nodes with
`aibom:systemRelationship`. AIBOM-aware validators SHOULD warn when no
system-boundary information is present.

Component versus service does not define system membership, ownership, control,
trust, or legal responsibility. Those are distinct axes.

External membership subtypes, such as `external-dependency`,
`external-actor`, and `environment-resource`, are deferred to v0.2.

### A21. Requirement Evidence Index Convention

The full Requirement Evidence Index profile is deferred to v0.2 or a companion
specification. v0.1 reserves only a documentation convention: external
requirement identifiers MAY be mapped to graph targets, declarations, evidence,
or external references.

Reserved factual statuses:

- `represented`;
- `evidence-linked`;
- `not-applicable`;
- `redacted`;
- `outside-scope`;
- `unknown`.

No status implies compliance, adequacy, legal sufficiency, or control
effectiveness. The v0.1 convention is evidence-targeting only. It is not a
conformance profile, compliance profile, or assurance profile.

## Part B — Hosted Model Representation

A hosted model accessed through a provider-controlled endpoint is represented
as a `service` for data-movement truth. The dataflow edge from the consuming
system targets the provider endpoint or provider resource.

The service:

- SHALL identify the served model through required `aibom:modelRef` to a
  `machine-learning-model` component, or through equivalent inline model
  identity;
- SHOULD carry `aibom:serviceRole=model-serving`;
- SHOULD carry `aibom:systemRelationship=constituent` when the BOM's declared
  scope includes the hosted model capability as part of the AI system, and
  `external` when the scope treats it as an outside interaction;
- carries provider, trust-boundary, and trust-zone information using existing
  CycloneDX fields where available.

The model component remains first-class for model-card metadata, ML-BOM
metadata, provenance, and evaluation metadata. A local model artifact is a
`component`.

A service-to-model `dataFlow` MAY be added as a clearly qualified declared
logical handoff. It MUST NOT be read as provider-internal deployment topology
unless the graph self-description and evidence support that interpretation.

## Part C — Consolidated `dataFlow` Entry Schema

```text
dataFlow {
  bom-ref:       refType      (REQUIRED -- stable edge id)
  source:        refLinkType  (REQUIRED)
  target:        refLinkType  (REQUIRED)
  operations:    array of enum [read, write, execute, delete]            (OPTIONAL)
  dataRefs:      array of refLinkType                                    (OPTIONAL)
  data:          array of serviceData-shaped descriptor                  (OPTIONAL)
  name:          string                                                  (OPTIONAL)
  description:   string                                                  (OPTIONAL)
  properties:    array of property                                       (OPTIONAL)
}
```

`bom-ref` is required for native `dataFlow` entries. In the CycloneDX
1.7-compatible Core property encoding, the canonical decoded target id is
`aibom:dataFlow:{compat-id}`.

`operations[]` is optional and should be populated only when the edge records
producer-declared interaction intent such as read, write, delete, or execute
with respect to the target as a resource, interface, store, actor, tool,
service, workflow, or other action-bearing endpoint.

Per-edge evidence attaches via declarations or external evidence references
targeting the edge. No native `dataFlow.evidence` field is proposed in v0.1.

`aibom:systemRelationship` and `aibom:serviceRole` are node properties, not edge
fields. No `purpose` field is proposed in v0.1.

## Part D — Delivery And Conformance

### D1. Three-Layer Model

AIBOM v0.1 should be defined as three layers:

1. **Abstract AIBOM information model:** nodes, directed `dataFlows[]`, Graph
   Self-Description, `systemRelationship`, data references, target-interaction
   operation annotations, trust context, and evidence targetability.
2. **Native CycloneDX 1.8 target encoding:** the clean schema form to propose
   upstream.
3. **CycloneDX 1.7-compatible `properties[]` encoding:** the deployable bridge
   so v0.1 can be emitted and tested before native fields land.

The 1.7 compatibility encoding is normative enough for interoperability, but
it is an encoding of the abstract model. It does not constrain the native 1.8
model.

### D2. AIBOM Core And AIBOM Enriched

v0.1 defines two implementation tiers.

**AIBOM Core** is the mandatory floor and depends only on constructs supported
by the current reference library surface: components, services, BOM-level
properties, node properties, and property-encoded dataflow edges with canonical
decoded edge target ids.

**AIBOM Enriched** is recommended and schema-aligned. It uses declarations,
compositions, and formulation where library support exists. Enriched features
degrade to their Core encoding, never to nothing.

Tier is not assurance. A Core AIBOM can be a full producer assertion. Enriched
can attach stronger machine-readable evidence. Confidence depends on
completeness, provenance, evidence quality, and producer trust, not the tier
label.

For EU AI Act / Annex IV review, Enriched is the recommended target where
tooling supports it because declarations, compositions, and formulation improve
reviewability.

### D3. Decoded Edge Targetability

The CycloneDX 1.7-compatible encoding MUST decode faithfully into the same
abstract `dataFlow` edge objects as the native encoding. A property-encoded edge
MUST be a referenceable graph target.

The property group `aibom:dataFlow:{compat-id}:*` decodes into one logical
`dataFlow` edge. `{compat-id}` identifies the property group. The canonical
Core decoded target id is `aibom:dataFlow:{compat-id}`.

Declarations, requirement mappings, findings, suppressions, and compositions
MAY target that decoded id under AIBOM-aware validation. Generic CycloneDX
consumers MAY ignore it. AIBOM-aware consumers MUST resolve it.

Do not use a `urn:` form for this local decoded target id. CycloneDX BOM-Link
already uses `urn:cdx:` for cross-document references.

### D4. Native Schema Deltas

The native CycloneDX 1.8 proposal should be filed as discrete schema issues.
The minimal native delta is expected to include `dataFlows[]` and any trust-zone
or data-reference fields that cannot be represented cleanly with existing
schema.

The property vocabulary should not be treated as an ungoverned private dialect.
The `aibom:` namespace should be registered in the CycloneDX Property Taxonomy
before the `properties[]` encoding is treated as a normative wire format.

### D5. `formulation` Reconciliation

`formulation` records process lineage: how an object was created, assembled,
deployed, tested, certified, trained, or otherwise produced.

`dataFlows[]` records data-movement topology: what data moved between which
system nodes.

Training and fine-tuning systems often need both. `formulation` does not absorb
training dataflows, and `dataFlows[]` does not replace formulation process
lineage.

### D6. `compositions` Reconciliation

AIBOM Core carries completeness as `aibom:completeness`. AIBOM Enriched SHOULD
express the same abstract completeness claim with `compositions[].aggregate`
over the relevant graph target set where supported.

Consumers should treat the property and the composition as two encodings of one
abstract completeness claim. When both appear, AIBOM-aware validation should
check consistency.

## Part E — Deferred To v0.2 Or Companion Specifications

Deferred items:

- trust-zone hierarchy;
- off-path control `purpose` / `controlPurpose[]`;
- external membership subtypes;
- full Requirement Evidence Index profile;
- AI-native function or capability taxonomy, including where those labels
  attach;
- deterministic edge identity for high-volume graphs;
- native XML after XSD support;
- control-node semantics;
- trust-zone graph promotion.

## Part F — Open WG Actions

Before adoption as a WG draft, the following execution gates should be closed
or explicitly accepted as open work:

1. File the CycloneDX 1.8 native schema issues.
2. Register the `aibom:` property namespace in the CycloneDX Property Taxonomy.
3. Write the `formulation` reconciliation section.
4. Write the `compositions` reconciliation section.
5. Add worked examples for hosted inference and training/fine-tuning pipelines.
6. Reconcile implementation plans and prototypes with this proposal.
