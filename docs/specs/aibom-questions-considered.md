# AIBOM Questions Considered and Resolutions

**Status:** Decision record for WG circulation proposal
**Date:** 2026-05-21
**Owner:** AIBOM draft editor
**Related proposal:** `aibom-draft-v1.md`

## Purpose

This document records the main design questions considered while developing the
AIBOM v0.1 system-structure proposal for Working Group circulation. It is a
decision record, not a replacement for the proposal and not a normative
specification by itself.

**Owner:** the AIBOM draft editor.
**Boundary:** records questions, alternatives, resolutions, and follow-up
actions for the system-structure delta. It does not define compliance,
assurance level, policy findings, or legal conclusions.
**Verification:** compare each entry against `aibom-draft-v1.md` and the
WG circulation text before publication. External legal or regulatory claims
need either a cited source or an explicit verification action.
**Required action:** keep this file aligned when the WG proposal changes.

## QC-01: Should AIBOM describe an AI system graph?

**Question:** Should AIBOM encode system structure, or should it avoid graph
semantics because a BOM is traditionally an inventory?

**Resolution:** AIBOM v0.1 proceeds as a system-structure graph. The working
premise is that the OWASP AIBOM effort needs to describe AI system structure,
including components, services, data movement, boundary context, and evidence
targets. AIBOM is graph-capable across scopes, but an AIBOM that
declares AI system scope or AIBOM System Structure conformance is graph-bearing:
it must include or normatively reference system-structure graph content
sufficient for the declared scope and completeness claim.

**Reasoning:** Without graph structure, the AIBOM cannot answer basic review
questions such as where data goes, which model or service receives it, what
crosses a trust boundary, or which evidence attaches to a specific interaction.

## QC-02: Should Core encode policy or compliance verdicts?

**Question:** Should AIBOM Core encode risk scores, compliance status, control
effectiveness, or legal conclusions?

**Resolution:** No. AIBOM Core standardizes the factual system-structure
substrate and self-description needed for later analysis. It does not encode
policy verdicts, risk scores, control efficacy, compliance findings, or legal
conclusions.

**Reasoning:** A policy evaluator needs targetable facts and evidence, not
vendor-selected conclusions embedded into the base graph. This keeps AIBOM
usable across jurisdictions, policies, and assurance regimes.

## QC-03: What minimum self-description must a graph carry?

**Question:** What must a consumer know before interpreting an AIBOM graph?

**Resolution:** AIBOM requires a Graph Self-Description block with four axes:
`graphType`, `generationMethod`, `scope`, and `completeness`. This is the only
mandatory new document-level addition; it does not make graph content optional
for AI-system-scope or AIBOM System Structure conformance.

**Reasoning:** A graph cannot support reliable negative inferences unless the
consumer knows what kind of graph it is, how it was generated, what scope it
claims to cover, and whether it is complete for that scope.

## QC-04: What does absence of a dataflow mean?

**Question:** May a consumer infer that no data movement exists because no
`dataFlows[]` edge is present?

**Resolution:** Only when the graph carries a completeness claim that supports
the inference for the relevant declared scope and graph target set. Incomplete,
redacted, or unknown graphs cannot support negative assurance. Observed-window
graphs support negative inference only when the completeness claim covers the
exact observation window, declared scope, graph type, and target set relevant to
the query.

**Reasoning:** The same graph can support positive findings even when
incomplete, but absence is only meaningful inside the specific completeness
boundary asserted by the producer.

## QC-05: Should dataflow evidence be a native edge field?

**Question:** Should each `dataFlow` edge carry its own `evidence` field?

**Resolution:** No native `dataFlow.evidence` field in v0.1. The requirement is
per-edge attestability. AIBOM Core reserves stable decoded edge targets and may
point to external evidence. AIBOM Enriched uses CycloneDX `declarations`
targeting those edge ids.

**Reasoning:** This preserves edge-level evidence without adding a new native
field and aligns evidence with the broader CycloneDX declaration model.

## QC-06: Should edge payloads be describable on the edge?

**Question:** Are endpoint data descriptors enough, or must the edge describe
what moved?

**Resolution:** Edges may carry plural `dataRefs[]` and optional inline `data[]`
descriptors.

**Reasoning:** Policy, security, and architecture review often turn on the
post-filter, post-redaction, post-embedding, or post-retrieval payload, not only
on endpoint-level data types.

## QC-07: Should AIBOM define AI-native operations in v0.1?

**Question:** Should v0.1 define `aiOperations[]`, `aiFunctions[]`, or a
node-level AI capability vocabulary for functions such as inference, embedding,
retrieval, ranking, training, fine-tuning, and evaluation?

**Resolution:** No. AIBOM v0.1 does not define AI-native operation fields or a
component capability taxonomy. Those concepts are deferred. The v0.1 graph
records data movement, target identity, evidence targets, scope, and
completeness. Optional `operations[]` remains narrow: it records declared
interaction intent with respect to the target as a resource, interface, store,
actor, tool, service, workflow, or other action-bearing endpoint.

**Reasoning:** AI function labels are useful, but component capability modeling
is beyond the v0.1 system-structure floor. Putting AI functions on edges would
also blur movement and processing: data moves on the edge, while ordinary
system behavior happens at the node.

## QC-08: How should hosted model APIs be represented?

**Question:** Should a hosted model accessed through a provider-controlled API
be modeled as a component, a service, or producer choice?

**Resolution:** Service-first for the data-movement graph. The provider
endpoint is represented as a service. The service must identify the served
model via `aibom:modelRef` or inline model identity. The model remains
first-class as a `machine-learning-model` component when model identity,
provenance, model-card metadata, or evaluation metadata is material.

**Reasoning:** Data movement terminates at the provider-controlled endpoint.
At the same time, reviewers must be able to enumerate and inspect the model
capability in one hop.

## QC-09: Does component versus service define system membership?

**Question:** Does representing something as a component or service determine
whether it is part of the described AI system?

**Resolution:** No. Node kind and system membership are orthogonal. AIBOM
defines optional `aibom:systemRelationship` with `constituent` and `external`
values. Absence means unspecified, not constituent by default.

For AI-system-scope BOMs with material external services, hosted model
endpoints, tools, data stores, actors, or other boundary-crossing nodes,
producers should classify material graph nodes and AIBOM-aware validators
should warn when no system-boundary information is present.

**Reasoning:** Component/service is about how something appears in the
data-movement graph. System membership is scope-relative and does not imply
ownership, operational control, trust, jurisdiction, legal responsibility, or
evidence of provider-internal topology.

## QC-10: How should external requirement mappings be handled?

**Question:** Should AIBOM map external requirements, such as EU AI Act Annex IV
documentation items, to graph targets and evidence?

**Resolution:** v0.1 reserves the Requirement Evidence Index convention as
documentation. The full profile is deferred to v0.2 or a companion
specification. Reserved statuses are factual only, such as `represented`,
`evidence-linked`, `not-applicable`, `redacted`, `outside-scope`, and
`unknown`. The v0.1 convention is evidence-targeting only. It is not a
conformance profile, compliance profile, or assurance profile.

**Reasoning:** Requirement-to-evidence mapping is essential for efficient
review, but it must remain an evidence index rather than a compliance layer.

## QC-11: How should completeness be encoded?

**Question:** Is completeness a BOM-level property, a CycloneDX composition, or
both?

**Resolution:** AIBOM Core carries `aibom:completeness` as a property whose
values map to CycloneDX `aggregateType` semantics. AIBOM Enriched expresses the
same claim with `compositions[].aggregate` over the relevant graph target set
where supported. In Core, unless a narrower target set is declared,
`aibom:completeness` applies to all AIBOM graph objects within the declared
`scope`, including decoded `dataFlow` edges, graph-participating nodes, and
required self-description axes.

**Reasoning:** This keeps Core emit-able from the current reference library
while preserving a schema-aligned expression for richer review artifacts.

## QC-12: How do `formulation` and `dataFlows[]` relate?

**Question:** Should CycloneDX `formulation` absorb training and build
pipelines, or should AIBOM still use dataflow edges?

**Resolution:** Both are needed. `formulation` describes process lineage and
how an object was created. `dataFlows[]` describes data movement topology.
AIBOM Core can express training data movement with property-encoded
`dataFlows`; AIBOM Enriched adds `formulation` lineage where supported.

**Reasoning:** A training system must be reviewable both as a process and as a
set of data movements.

## QC-13: How should v0.1 balance CycloneDX 1.8 design and 1.7 compatibility?

**Question:** Should the v0.1 model be constrained by CycloneDX 1.7 property
encoding, or should it target a clean 1.8 native model?

**Resolution:** AIBOM uses three layers: a forward-designed abstract
information model, a proposed native CycloneDX 1.8 encoding, and a normative
CycloneDX 1.7-compatible `properties[]` encoding.

**Reasoning:** The model should not be contorted around 1.7 limitations, but
the working group still needs a deployable and testable compatibility encoding
before native 1.8 fields exist.

## QC-14: Are property-encoded edges real graph targets?

**Question:** If v0.1 uses `properties[]` to encode `dataFlow` edges, can those
edges be referenced by evidence, requirements, findings, suppressions, and
compositions?

**Resolution:** Yes. The property group
`aibom:dataFlow:{compat-id}:*` decodes into one logical dataflow edge, and
`{compat-id}` identifies the property group. The stable canonical Core decoded
target id is `aibom:dataFlow:{compat-id}`. AIBOM should not use a `urn:` form
for this local decoded target because CycloneDX BOM-Link already uses `urn:cdx:`
for cross-document references.

**Reasoning:** If property-encoded edges are not first-class logical targets,
the compatibility encoding cannot support per-edge evidence, requirement
mapping, findings, or validation.

## QC-15: How should v0.1 stay implementable in `cyclonedx-python-lib`?

**Question:** Does a schema-free design mean v0.1 is library-free?

**Resolution:** No. v0.1 uses two implementation tiers. AIBOM Core is the
mandatory floor and is emit-able today with supported constructs: components,
services, BOM and node properties, and property-encoded dataflow edges. AIBOM
Enriched uses declarations, compositions, and formulation where library support
exists.

**Reasoning:** `declarations`, `compositions`, and `formulation` are
schema-aligned but currently unsupported in this library. The conformance model
must describe that implementation cost honestly.

## QC-16: Does Core versus Enriched imply assurance level?

**Question:** Is an Enriched AIBOM automatically higher assurance than a Core
AIBOM?

**Resolution:** No. Tier is about encoding and library support, not confidence
or assurance. A Core AIBOM can be a complete producer assertion. Enriched can
attach stronger machine-readable evidence, but confidence comes from
completeness, provenance, evidence quality, and producer trust.

**Reasoning:** Treating the tier label as assurance would recreate the policy
verdict problem under a different name.

## QC-17: Should the `aibom:` property vocabulary be governed?

**Question:** If the 1.7 compatibility encoding is normative, how should the
property namespace be managed?

**Resolution:** Register the `aibom:` property vocabulary in the CycloneDX
Property Taxonomy before treating the properties encoding as a normative wire
format.

**Reasoning:** A normative property vocabulary without namespace governance
would create the same ad-hoc fragmentation that native schema work is meant to
avoid.

## QC-18: What is deferred from v0.1?

**Question:** Which useful ideas are intentionally out of the v0.1
system-structure delta?

**Resolution:** Deferred items include trust-zone hierarchy, off-path
`purpose` or `controlPurpose[]`, external membership subtypes, the full
Requirement Evidence Index profile, deterministic edge identity for high-volume
graphs, control-node semantics, and trust-zone graph promotion.

**Reasoning:** These are valid issues, but including all of them would expand
v0.1 beyond the field freeze and implementation budget.

## QC-19: What remains before WG circulation?

**Question:** Is the proposal ready for WG circulation?

**Resolution:** The substantive design direction is ready for WG circulation as
a proposal. Remaining work is execution-gated: file the CycloneDX 1.8 native
schema issues, register the `aibom:` property namespace, write the
`formulation` and `compositions` reconciliation sections, add worked examples,
and reconcile implementation and prototype notes with the proposal text.

**Reasoning:** Circulation readiness and implementation readiness are different
gates. The decision record should not present delivery tasks as unresolved
design questions.

## QC-20: Are trust zones absolute?

**Question:** Can a trust-zone label be interpreted without knowing the
producer or evaluator perspective?

**Resolution:** No. Trust zones are producer-relative. When trust zones are
used, the AIBOM should declare `aibom:trustPerspective` so consumers know whose
trust frame is being represented.

**Reasoning:** A provider-internal BOM and a consumer-facing BOM can both be
correct while assigning the same node to different zones.

## QC-21: Should trust zones become a graph in v0.1?

**Question:** Should trust-zone hierarchy or trust-zone graph promotion be part
of the initial system-structure delta?

**Resolution:** No. Trust zones remain contextual metadata in v0.1. Trust-zone
hierarchy and graph promotion are deferred.

**Reasoning:** The base graph already carries enough new structure. Promoting
trust zones to their own hierarchy would expand v0.1 without being required for
the settled graph model.

## QC-22: What do `operations[]` mean?

**Question:** Do operations determine direction or classify the node?

**Resolution:** No. Operations record producer-declared interaction intent with
respect to the target as a resource, interface, store, actor, tool, service,
workflow, or other action-bearing endpoint. They do not classify node
capabilities or ordinary internal processing behavior. Dataflow direction
remains `source` to `target`. Request and response movements should be
represented as separate unidirectional edges when both are material.

**Reasoning:** Direction, target-interaction intent, and node behavior are
distinct facts. Combining them would make request/response, boundary, and
internal-processing cases ambiguous.

## QC-23: What does `execute` mean?

**Question:** Does `execute` apply whenever an internal pipeline component
processes input?

**Resolution:** No. `execute` means the data movement records an intent to
invoke target functionality whose material effect is an action, workflow,
downstream behavior, or state transition beyond passive receipt, storage, or
ordinary computation over the received data. It does not apply merely because a
component filters, transforms, embeds, ranks, infers, or otherwise computes over
data as part of the pipeline.

**Reasoning:** Without this constraint, `execute` would become a vague synonym
for processing. With the target-interaction wording, action-bearing invocation
can still be visible without treating ordinary AI computation as `execute`.

## QC-24: Can `metadata.component` be a graph node?

**Question:** Should `metadata.component` participate as an ordinary runtime
node in the AIBOM graph?

**Resolution:** Only when the BOM subject is itself a runtime participant.
Otherwise, producers should model runtime behavior with explicit component or
service nodes.

**Reasoning:** The BOM subject is document metadata by default. Treating it as
a runtime graph participant by implication would blur document subject and
system node semantics.

## QC-25: Is active/passive terminology normative?

**Question:** Should AIBOM classify nodes as active or passive?

**Resolution:** No. Active/passive language is explanatory only. Normative
behavior comes from incident edges and operation annotations.

**Reasoning:** Static node labels would under-describe real systems. The same
node can behave differently across different interactions.

## QC-26: Should native XML be required in v0.1?

**Question:** Does v0.1 need native XML support for new AIBOM fields?

**Resolution:** No. v0.1 should have a property-encoded XML compatibility
story. Native XML waits for the XSD changes.

**Reasoning:** Requiring native XML before the XSD exists would put unnecessary
delivery risk on v0.1.

## QC-27: What process gates remain after WG circulation?

**Question:** What must happen after WG review begins and before treating the
v0.1 compatibility encoding and native schema path as ready for implementation?

**Resolution:** Resolve WG feedback, file the CycloneDX 1.8 native schema
issues, register the `aibom:` property namespace, write the `formulation`
reconciliation, write the `compositions` reconciliation, reconcile implementation
and prototype examples, and keep the v0.1 field set frozen unless an explicit
schema cost and offset are accepted.

**Reasoning:** These gates prevent the design from becoming either a private
property dialect or an under-specified schema proposal.

## QC-28: Does AIBOM solve ABOM or TM-BOM?

**Question:** Should AIBOM claim to solve adjacent Blueprints, ABOM, BOB, or
TM-BOM use cases?

**Resolution:** No. AIBOM graph primitives may provide a substrate for future
mapping work, but those adjacent efforts remain outside this document's scope.

**Reasoning:** Overclaiming adjacent standards would distract from the narrower
system-structure delta and create unnecessary review cost.

## Related Plans

- `docs/plans/2026-05-21-aibom-everett-policy-evaluation.md`
