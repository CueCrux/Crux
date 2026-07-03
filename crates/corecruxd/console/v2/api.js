// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.
//
// @generated — DO NOT EDIT BY HAND.
// Source of truth: the ROUTES manifest in crates/corecruxd/src/http/openapi.rs.
// Regenerate:
//   cargo test -p corecruxd --test route_spec_drift -- --ignored regen_api_js
//
// Customer-safe posture: CruxApi (below) exposes only GET (read) routes; its
// generic get(path) is allowlist-guarded to literal manifest GET paths. The ONLY
// writes this console can perform live in the separate CruxApiGated object at the
// bottom — exactly 4 curated, operator-posture-gated mutation(s), no more.
//
// Every call is same-origin credentialed; the browser never holds a bearer
// token (the daemon authenticates the session at its own origin).
//
// 149 read endpoints, generated from the route manifest.

/**
 * Append a plain query object to a path as a URL search string.
 * @param {string} path
 * @param {Object<string, (string|number|boolean)>} [query]
 * @returns {string}
 */
function withQuery(path, query) {
  if (!query) return path;
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null) usp.append(k, String(v));
  }
  const qs = usp.toString();
  return qs ? `${path}?${qs}` : path;
}

/**
 * Literal (parameter-free) GET paths from the manifest — the allowlist for
 * CruxApi.get(). Parameterised routes are reachable only via named methods.
 */
const LITERAL_GET_PATHS = Object.freeze({
  '/healthz': true,
  '/metrics': true,
  '/readyz': true,
  '/v1/activity': true,
  '/v1/admin/control': true,
  '/v1/admin/ops-log': true,
  '/v1/admin/projections/meta': true,
  '/v1/admin/projections/modules': true,
  '/v1/admin/replication/status': true,
  '/v1/admin/segments/fingerprints': true,
  '/v1/admin/sharing/posture': true,
  '/v1/admin/version': true,
  '/v1/auth/whoami': true,
  '/v1/bootstrap/status': true,
  '/v1/cloud/access-contract': true,
  '/v1/console/corecrux/lane-weights': true,
  '/v1/console/facts': true,
  '/v1/console/infra/summary': true,
  '/v1/console/integrations': true,
  '/v1/console/onboarding': true,
  '/v1/console/passports': true,
  '/v1/console/review/contradictions': true,
  '/v1/console/sessions': true,
  '/v1/console/settings': true,
  '/v1/console/storage-breakdown': true,
  '/v1/console/summary': true,
  '/v1/console/tenants': true,
  '/v1/context': true,
  '/v1/coord/active': true,
  '/v1/cost/report': true,
  '/v1/edges': true,
  '/v1/engrams': true,
  '/v1/entities': true,
  '/v1/events/stream': true,
  '/v1/extensions': true,
  '/v1/extensions/keys': true,
  '/v1/facts': true,
  '/v1/facts/export': true,
  '/v1/features/capabilities': true,
  '/v1/features/capabilities/analysis/coverage': true,
  '/v1/features/capabilities/analysis/gaps': true,
  '/v1/features/capabilities/analysis/promises': true,
  '/v1/gpu1/contract': true,
  '/v1/gpus': true,
  '/v1/identity/candidates': true,
  '/v1/identity/links': true,
  '/v1/integrations/github/repos': true,
  '/v1/integrations/github/repos/accessible': true,
  '/v1/integrations/github/status': true,
  '/v1/integrations/openai/status': true,
  '/v1/kinds': true,
  '/v1/mcp/tools': true,
  '/v1/observations/aggregate': true,
  '/v1/openai/tools.json': true,
  '/v1/openapi.json': true,
  '/v1/ops/errors': true,
  '/v1/ops/facts': true,
  '/v1/ops/health': true,
  '/v1/orchestrators': true,
  '/v1/passports': true,
  '/v1/passports/presence': true,
  '/v1/policy/capabilities': true,
  '/v1/principal/resolve': true,
  '/v1/projections/entity/count': true,
  '/v1/projections/entity/current-state': true,
  '/v1/projections/entity/timeline': true,
  '/v1/projects': true,
  '/v1/punchcards': true,
  '/v1/quota': true,
  '/v1/relations': true,
  '/v1/route': true,
  '/v1/routing/route': true,
  '/v1/routing/status': true,
  '/v1/sessions/active': true,
  '/v1/shard-map': true,
  '/v1/shards': true,
  '/v1/status-feed': true,
  '/v1/version': true,
  '/v1/witness/smoke': true,
  '/v1/work': true,
  '/v1/work/gate/pending': true,
  '/v1/workbench/api-drift': true,
  '/v1/workbench/audit-triage': true,
  '/v1/workbench/brief': true,
  '/v1/workbench/command-ledger': true,
  '/v1/workbench/contract': true,
  '/v1/workbench/reasoning-timeline': true,
  '/v1/workspace/scan': true,
  '/v1/workspace/storyline': true,
});

/**
 * Generated read-only client for the Crux daemon HTTP API.
 * One method per GET route; each returns the raw `fetch` Promise.
 */
const CruxApi = Object.freeze({
  /**
   * Allowlist-guarded generic read: only literal (parameter-free) GET paths
   * from the manifest are callable. Unknown paths reject without touching
   * the network. Parameterised routes: use their named methods below.
   * @param {string} path
   * @param {Object<string, (string|number|boolean)>} [query]
   * @returns {Promise<Response>}
   */
  get(path, query) {
    if (!LITERAL_GET_PATHS[path]) {
      return Promise.reject(new Error('CruxApi.get: path not in the generated GET allowlist: ' + path));
    }
    return fetch(withQuery(path, query), { credentials: 'same-origin' });
  },
  healthz(query) {
    return fetch(withQuery(`/healthz`, query), { credentials: 'same-origin' });
  },
  metrics(query) {
    return fetch(withQuery(`/metrics`, query), { credentials: 'same-origin' });
  },
  readyz(query) {
    return fetch(withQuery(`/readyz`, query), { credentials: 'same-origin' });
  },
  activity(query) {
    return fetch(withQuery(`/v1/activity`, query), { credentials: 'same-origin' });
  },
  activityTurnByTurnId(turn_id, query) {
    return fetch(withQuery(`/v1/activity/turn/${encodeURIComponent(turn_id)}`, query), { credentials: 'same-origin' });
  },
  activityTurnByTurnIdVerify(turn_id, query) {
    return fetch(withQuery(`/v1/activity/turn/${encodeURIComponent(turn_id)}/verify`, query), { credentials: 'same-origin' });
  },
  adminActionsByActionId(actionId, query) {
    return fetch(withQuery(`/v1/admin/actions/${encodeURIComponent(actionId)}`, query), { credentials: 'same-origin' });
  },
  adminControl(query) {
    return fetch(withQuery(`/v1/admin/control`, query), { credentials: 'same-origin' });
  },
  adminOpsLog(query) {
    return fetch(withQuery(`/v1/admin/ops-log`, query), { credentials: 'same-origin' });
  },
  adminProjectionsArtifactsByArtifactIdDependents(artifactId, query) {
    return fetch(withQuery(`/v1/admin/projections/artifacts/${encodeURIComponent(artifactId)}/dependents`, query), { credentials: 'same-origin' });
  },
  adminProjectionsArtifactsByArtifactIdPressureEvents(artifactId, query) {
    return fetch(withQuery(`/v1/admin/projections/artifacts/${encodeURIComponent(artifactId)}/pressure-events`, query), { credentials: 'same-origin' });
  },
  adminProjectionsArtifactsByArtifactIdRelations(artifactId, query) {
    return fetch(withQuery(`/v1/admin/projections/artifacts/${encodeURIComponent(artifactId)}/relations`, query), { credentials: 'same-origin' });
  },
  adminProjectionsArtifactsByArtifactIdState(artifactId, query) {
    return fetch(withQuery(`/v1/admin/projections/artifacts/${encodeURIComponent(artifactId)}/state`, query), { credentials: 'same-origin' });
  },
  adminProjectionsMeta(query) {
    return fetch(withQuery(`/v1/admin/projections/meta`, query), { credentials: 'same-origin' });
  },
  adminProjectionsModules(query) {
    return fetch(withQuery(`/v1/admin/projections/modules`, query), { credentials: 'same-origin' });
  },
  adminReplicationStatus(query) {
    return fetch(withQuery(`/v1/admin/replication/status`, query), { credentials: 'same-origin' });
  },
  adminSegmentsFingerprints(query) {
    return fetch(withQuery(`/v1/admin/segments/fingerprints`, query), { credentials: 'same-origin' });
  },
  adminSharingPosture(query) {
    return fetch(withQuery(`/v1/admin/sharing/posture`, query), { credentials: 'same-origin' });
  },
  adminVersion(query) {
    return fetch(withQuery(`/v1/admin/version`, query), { credentials: 'same-origin' });
  },
  agentsByPassportUsage(passport, query) {
    return fetch(withQuery(`/v1/agents/${encodeURIComponent(passport)}/usage`, query), { credentials: 'same-origin' });
  },
  authWhoami(query) {
    return fetch(withQuery(`/v1/auth/whoami`, query), { credentials: 'same-origin' });
  },
  bootstrapStatus(query) {
    return fetch(withQuery(`/v1/bootstrap/status`, query), { credentials: 'same-origin' });
  },
  cloudAccessContract(query) {
    return fetch(withQuery(`/v1/cloud/access-contract`, query), { credentials: 'same-origin' });
  },
  consoleChunksByChunkDigest(chunkDigest, query) {
    return fetch(withQuery(`/v1/console/chunks/${encodeURIComponent(chunkDigest)}`, query), { credentials: 'same-origin' });
  },
  consoleChunksByChunkDigestPreview(chunkDigest, query) {
    return fetch(withQuery(`/v1/console/chunks/${encodeURIComponent(chunkDigest)}/preview`, query), { credentials: 'same-origin' });
  },
  consoleCorecruxLaneWeights(query) {
    return fetch(withQuery(`/v1/console/corecrux/lane-weights`, query), { credentials: 'same-origin' });
  },
  consoleFacts(query) {
    return fetch(withQuery(`/v1/console/facts`, query), { credentials: 'same-origin' });
  },
  consoleInfraSummary(query) {
    return fetch(withQuery(`/v1/console/infra/summary`, query), { credentials: 'same-origin' });
  },
  consoleIntegrations(query) {
    return fetch(withQuery(`/v1/console/integrations`, query), { credentials: 'same-origin' });
  },
  consoleOnboarding(query) {
    return fetch(withQuery(`/v1/console/onboarding`, query), { credentials: 'same-origin' });
  },
  consolePassports(query) {
    return fetch(withQuery(`/v1/console/passports`, query), { credentials: 'same-origin' });
  },
  consoleReviewContradictions(query) {
    return fetch(withQuery(`/v1/console/review/contradictions`, query), { credentials: 'same-origin' });
  },
  consoleSessions(query) {
    return fetch(withQuery(`/v1/console/sessions`, query), { credentials: 'same-origin' });
  },
  consoleSettings(query) {
    return fetch(withQuery(`/v1/console/settings`, query), { credentials: 'same-origin' });
  },
  consoleStorageBreakdown(query) {
    return fetch(withQuery(`/v1/console/storage-breakdown`, query), { credentials: 'same-origin' });
  },
  consoleSummary(query) {
    return fetch(withQuery(`/v1/console/summary`, query), { credentials: 'same-origin' });
  },
  consoleTenants(query) {
    return fetch(withQuery(`/v1/console/tenants`, query), { credentials: 'same-origin' });
  },
  consoleTenantsByTenantIdCategory(tenantId, query) {
    return fetch(withQuery(`/v1/console/tenants/${encodeURIComponent(tenantId)}/category`, query), { credentials: 'same-origin' });
  },
  consoleTenantsByTenantIdChunks(tenantId, query) {
    return fetch(withQuery(`/v1/console/tenants/${encodeURIComponent(tenantId)}/chunks`, query), { credentials: 'same-origin' });
  },
  context(query) {
    return fetch(withQuery(`/v1/context`, query), { credentials: 'same-origin' });
  },
  coordActive(query) {
    return fetch(withQuery(`/v1/coord/active`, query), { credentials: 'same-origin' });
  },
  costReport(query) {
    return fetch(withQuery(`/v1/cost/report`, query), { credentials: 'same-origin' });
  },
  edges(query) {
    return fetch(withQuery(`/v1/edges`, query), { credentials: 'same-origin' });
  },
  engrams(query) {
    return fetch(withQuery(`/v1/engrams`, query), { credentials: 'same-origin' });
  },
  entities(query) {
    return fetch(withQuery(`/v1/entities`, query), { credentials: 'same-origin' });
  },
  entitiesByKindById(kind, id, query) {
    return fetch(withQuery(`/v1/entities/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`, query), { credentials: 'same-origin' });
  },
  entitiesByKindByIdHistory(kind, id, query) {
    return fetch(withQuery(`/v1/entities/${encodeURIComponent(kind)}/${encodeURIComponent(id)}/history`, query), { credentials: 'same-origin' });
  },
  eventsStream(query) {
    return fetch(withQuery(`/v1/events/stream`, query), { credentials: 'same-origin' });
  },
  extensions(query) {
    return fetch(withQuery(`/v1/extensions`, query), { credentials: 'same-origin' });
  },
  extensionsKeys(query) {
    return fetch(withQuery(`/v1/extensions/keys`, query), { credentials: 'same-origin' });
  },
  extensionsById(id, query) {
    return fetch(withQuery(`/v1/extensions/${encodeURIComponent(id)}`, query), { credentials: 'same-origin' });
  },
  extensionsByIdGrants(id, query) {
    return fetch(withQuery(`/v1/extensions/${encodeURIComponent(id)}/grants`, query), { credentials: 'same-origin' });
  },
  facts(query) {
    return fetch(withQuery(`/v1/facts`, query), { credentials: 'same-origin' });
  },
  factsEntityByEntity(entity, query) {
    return fetch(withQuery(`/v1/facts/entity/${encodeURIComponent(entity)}`, query), { credentials: 'same-origin' });
  },
  factsExport(query) {
    return fetch(withQuery(`/v1/facts/export`, query), { credentials: 'same-origin' });
  },
  factsByFactId(factId, query) {
    return fetch(withQuery(`/v1/facts/${encodeURIComponent(factId)}`, query), { credentials: 'same-origin' });
  },
  featuresCapabilities(query) {
    return fetch(withQuery(`/v1/features/capabilities`, query), { credentials: 'same-origin' });
  },
  featuresCapabilitiesAnalysisCoverage(query) {
    return fetch(withQuery(`/v1/features/capabilities/analysis/coverage`, query), { credentials: 'same-origin' });
  },
  featuresCapabilitiesAnalysisGaps(query) {
    return fetch(withQuery(`/v1/features/capabilities/analysis/gaps`, query), { credentials: 'same-origin' });
  },
  featuresCapabilitiesAnalysisPromises(query) {
    return fetch(withQuery(`/v1/features/capabilities/analysis/promises`, query), { credentials: 'same-origin' });
  },
  featuresCapabilitiesById(id, query) {
    return fetch(withQuery(`/v1/features/capabilities/${encodeURIComponent(id)}`, query), { credentials: 'same-origin' });
  },
  featuresCapabilitiesByIdTree(id, query) {
    return fetch(withQuery(`/v1/features/capabilities/${encodeURIComponent(id)}/tree`, query), { credentials: 'same-origin' });
  },
  gpu1Contract(query) {
    return fetch(withQuery(`/v1/gpu1/contract`, query), { credentials: 'same-origin' });
  },
  gpus(query) {
    return fetch(withQuery(`/v1/gpus`, query), { credentials: 'same-origin' });
  },
  identityCandidates(query) {
    return fetch(withQuery(`/v1/identity/candidates`, query), { credentials: 'same-origin' });
  },
  identityLinks(query) {
    return fetch(withQuery(`/v1/identity/links`, query), { credentials: 'same-origin' });
  },
  integrationsGithubRepos(query) {
    return fetch(withQuery(`/v1/integrations/github/repos`, query), { credentials: 'same-origin' });
  },
  integrationsGithubReposAccessible(query) {
    return fetch(withQuery(`/v1/integrations/github/repos/accessible`, query), { credentials: 'same-origin' });
  },
  integrationsGithubStatus(query) {
    return fetch(withQuery(`/v1/integrations/github/status`, query), { credentials: 'same-origin' });
  },
  integrationsOpenaiStatus(query) {
    return fetch(withQuery(`/v1/integrations/openai/status`, query), { credentials: 'same-origin' });
  },
  kinds(query) {
    return fetch(withQuery(`/v1/kinds`, query), { credentials: 'same-origin' });
  },
  kindsByKind(kind, query) {
    return fetch(withQuery(`/v1/kinds/${encodeURIComponent(kind)}`, query), { credentials: 'same-origin' });
  },
  mcpTools(query) {
    return fetch(withQuery(`/v1/mcp/tools`, query), { credentials: 'same-origin' });
  },
  observationsAggregate(query) {
    return fetch(withQuery(`/v1/observations/aggregate`, query), { credentials: 'same-origin' });
  },
  observeSessionsByIdAudit(id, query) {
    return fetch(withQuery(`/v1/observe/sessions/${encodeURIComponent(id)}/audit`, query), { credentials: 'same-origin' });
  },
  observeSessionsByIdAuditConformance(id, query) {
    return fetch(withQuery(`/v1/observe/sessions/${encodeURIComponent(id)}/audit/conformance`, query), { credentials: 'same-origin' });
  },
  observeSessionsByIdAuditExport(id, query) {
    return fetch(withQuery(`/v1/observe/sessions/${encodeURIComponent(id)}/audit/export`, query), { credentials: 'same-origin' });
  },
  openaiToolsJson(query) {
    return fetch(withQuery(`/v1/openai/tools.json`, query), { credentials: 'same-origin' });
  },
  openapiJson(query) {
    return fetch(withQuery(`/v1/openapi.json`, query), { credentials: 'same-origin' });
  },
  opsErrors(query) {
    return fetch(withQuery(`/v1/ops/errors`, query), { credentials: 'same-origin' });
  },
  opsFacts(query) {
    return fetch(withQuery(`/v1/ops/facts`, query), { credentials: 'same-origin' });
  },
  opsHealth(query) {
    return fetch(withQuery(`/v1/ops/health`, query), { credentials: 'same-origin' });
  },
  orchestrators(query) {
    return fetch(withQuery(`/v1/orchestrators`, query), { credentials: 'same-origin' });
  },
  orchestratorsById(id, query) {
    return fetch(withQuery(`/v1/orchestrators/${encodeURIComponent(id)}`, query), { credentials: 'same-origin' });
  },
  orchestratorsByIdWork(id, query) {
    return fetch(withQuery(`/v1/orchestrators/${encodeURIComponent(id)}/work`, query), { credentials: 'same-origin' });
  },
  passports(query) {
    return fetch(withQuery(`/v1/passports`, query), { credentials: 'same-origin' });
  },
  passportsPresence(query) {
    return fetch(withQuery(`/v1/passports/presence`, query), { credentials: 'same-origin' });
  },
  passportsByPassportId(passportId, query) {
    return fetch(withQuery(`/v1/passports/${encodeURIComponent(passportId)}`, query), { credentials: 'same-origin' });
  },
  policyCapabilities(query) {
    return fetch(withQuery(`/v1/policy/capabilities`, query), { credentials: 'same-origin' });
  },
  principalResolve(query) {
    return fetch(withQuery(`/v1/principal/resolve`, query), { credentials: 'same-origin' });
  },
  projectionsEntityCount(query) {
    return fetch(withQuery(`/v1/projections/entity/count`, query), { credentials: 'same-origin' });
  },
  projectionsEntityCurrentState(query) {
    return fetch(withQuery(`/v1/projections/entity/current-state`, query), { credentials: 'same-origin' });
  },
  projectionsEntityTimeline(query) {
    return fetch(withQuery(`/v1/projections/entity/timeline`, query), { credentials: 'same-origin' });
  },
  projects(query) {
    return fetch(withQuery(`/v1/projects`, query), { credentials: 'same-origin' });
  },
  projectsById(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}`, query), { credentials: 'same-origin' });
  },
  projectsByIdContextGraph(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/context-graph`, query), { credentials: 'same-origin' });
  },
  projectsByIdDossiers(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/dossiers`, query), { credentials: 'same-origin' });
  },
  projectsByIdDossiersDiff(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/dossiers/diff`, query), { credentials: 'same-origin' });
  },
  projectsByIdDossiersReconcile(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/dossiers/reconcile`, query), { credentials: 'same-origin' });
  },
  projectsByIdDossiersByDossierId(id, dossierId, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/dossiers/${encodeURIComponent(dossierId)}`, query), { credentials: 'same-origin' });
  },
  projectsByIdLayers(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/layers`, query), { credentials: 'same-origin' });
  },
  projectsByIdPlanes(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/planes`, query), { credentials: 'same-origin' });
  },
  projectsByIdPlanesByPlaneId(id, planeId, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/planes/${encodeURIComponent(planeId)}`, query), { credentials: 'same-origin' });
  },
  projectsByIdPlanesByPlaneIdLayers(id, planeId, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/planes/${encodeURIComponent(planeId)}/layers`, query), { credentials: 'same-origin' });
  },
  projectsByIdPlanesByPlaneIdRepos(id, planeId, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/planes/${encodeURIComponent(planeId)}/repos`, query), { credentials: 'same-origin' });
  },
  projectsByIdRepos(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/repos`, query), { credentials: 'same-origin' });
  },
  projectsByIdStorybook(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/storybook`, query), { credentials: 'same-origin' });
  },
  projectsByIdStorybookDiff(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/storybook/diff`, query), { credentials: 'same-origin' });
  },
  projectsByIdStorybookVersions(id, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/storybook/versions`, query), { credentials: 'same-origin' });
  },
  projectsByIdStorybookByTs(id, ts, query) {
    return fetch(withQuery(`/v1/projects/${encodeURIComponent(id)}/storybook/${encodeURIComponent(ts)}`, query), { credentials: 'same-origin' });
  },
  punchcards(query) {
    return fetch(withQuery(`/v1/punchcards`, query), { credentials: 'same-origin' });
  },
  quota(query) {
    return fetch(withQuery(`/v1/quota`, query), { credentials: 'same-origin' });
  },
  receiptsByReceiptId(receiptId, query) {
    return fetch(withQuery(`/v1/receipts/${encodeURIComponent(receiptId)}`, query), { credentials: 'same-origin' });
  },
  receiptsByReceiptIdSignature(receiptId, query) {
    return fetch(withQuery(`/v1/receipts/${encodeURIComponent(receiptId)}/signature`, query), { credentials: 'same-origin' });
  },
  receiptsByReceiptIdVerification(receiptId, query) {
    return fetch(withQuery(`/v1/receipts/${encodeURIComponent(receiptId)}/verification`, query), { credentials: 'same-origin' });
  },
  relations(query) {
    return fetch(withQuery(`/v1/relations`, query), { credentials: 'same-origin' });
  },
  replayAnswersByAnswerId(answerId, query) {
    return fetch(withQuery(`/v1/replay/answers/${encodeURIComponent(answerId)}`, query), { credentials: 'same-origin' });
  },
  replayAnswersByAnswerIdValidity(answerId, query) {
    return fetch(withQuery(`/v1/replay/answers/${encodeURIComponent(answerId)}/validity`, query), { credentials: 'same-origin' });
  },
  replayExportsActionsByActionId(actionId, query) {
    return fetch(withQuery(`/v1/replay/exports/actions/${encodeURIComponent(actionId)}`, query), { credentials: 'same-origin' });
  },
  replayExportsAnswersByAnswerId(answerId, query) {
    return fetch(withQuery(`/v1/replay/exports/answers/${encodeURIComponent(answerId)}`, query), { credentials: 'same-origin' });
  },
  replayExportsReceiptsByReceiptId(receiptId, query) {
    return fetch(withQuery(`/v1/replay/exports/receipts/${encodeURIComponent(receiptId)}`, query), { credentials: 'same-origin' });
  },
  replayExportsStreamsByStreamTypeByStreamId(streamType, streamId, query) {
    return fetch(withQuery(`/v1/replay/exports/streams/${encodeURIComponent(streamType)}/${encodeURIComponent(streamId)}`, query), { credentials: 'same-origin' });
  },
  route(query) {
    return fetch(withQuery(`/v1/route`, query), { credentials: 'same-origin' });
  },
  routingRoute(query) {
    return fetch(withQuery(`/v1/routing/route`, query), { credentials: 'same-origin' });
  },
  routingStatus(query) {
    return fetch(withQuery(`/v1/routing/status`, query), { credentials: 'same-origin' });
  },
  sessionsActive(query) {
    return fetch(withQuery(`/v1/sessions/active`, query), { credentials: 'same-origin' });
  },
  sessionsBySessionIdObservations(sessionId, query) {
    return fetch(withQuery(`/v1/sessions/${encodeURIComponent(sessionId)}/observations`, query), { credentials: 'same-origin' });
  },
  sessionsBySessionIdPlan(sessionId, query) {
    return fetch(withQuery(`/v1/sessions/${encodeURIComponent(sessionId)}/plan`, query), { credentials: 'same-origin' });
  },
  sessionsBySessionIdState(sessionId, query) {
    return fetch(withQuery(`/v1/sessions/${encodeURIComponent(sessionId)}/state`, query), { credentials: 'same-origin' });
  },
  shardMap(query) {
    return fetch(withQuery(`/v1/shard-map`, query), { credentials: 'same-origin' });
  },
  shards(query) {
    return fetch(withQuery(`/v1/shards`, query), { credentials: 'same-origin' });
  },
  statusFeed(query) {
    return fetch(withQuery(`/v1/status-feed`, query), { credentials: 'same-origin' });
  },
  syncTenantsByTenantIdCollectionsByCollection(tenantId, collection, query) {
    return fetch(withQuery(`/v1/sync/tenants/${encodeURIComponent(tenantId)}/collections/${encodeURIComponent(collection)}`, query), { credentials: 'same-origin' });
  },
  syncTenantsByTenantIdManifest(tenantId, query) {
    return fetch(withQuery(`/v1/sync/tenants/${encodeURIComponent(tenantId)}/manifest`, query), { credentials: 'same-origin' });
  },
  version(query) {
    return fetch(withQuery(`/v1/version`, query), { credentials: 'same-origin' });
  },
  witnessSmoke(query) {
    return fetch(withQuery(`/v1/witness/smoke`, query), { credentials: 'same-origin' });
  },
  work(query) {
    return fetch(withQuery(`/v1/work`, query), { credentials: 'same-origin' });
  },
  workGatePending(query) {
    return fetch(withQuery(`/v1/work/gate/pending`, query), { credentials: 'same-origin' });
  },
  workById(id, query) {
    return fetch(withQuery(`/v1/work/${encodeURIComponent(id)}`, query), { credentials: 'same-origin' });
  },
  workByIdComments(id, query) {
    return fetch(withQuery(`/v1/work/${encodeURIComponent(id)}/comments`, query), { credentials: 'same-origin' });
  },
  workByIdTransitions(id, query) {
    return fetch(withQuery(`/v1/work/${encodeURIComponent(id)}/transitions`, query), { credentials: 'same-origin' });
  },
  workbenchApiDrift(query) {
    return fetch(withQuery(`/v1/workbench/api-drift`, query), { credentials: 'same-origin' });
  },
  workbenchAuditTriage(query) {
    return fetch(withQuery(`/v1/workbench/audit-triage`, query), { credentials: 'same-origin' });
  },
  workbenchBrief(query) {
    return fetch(withQuery(`/v1/workbench/brief`, query), { credentials: 'same-origin' });
  },
  workbenchCommandLedger(query) {
    return fetch(withQuery(`/v1/workbench/command-ledger`, query), { credentials: 'same-origin' });
  },
  workbenchContract(query) {
    return fetch(withQuery(`/v1/workbench/contract`, query), { credentials: 'same-origin' });
  },
  workbenchReasoningTimeline(query) {
    return fetch(withQuery(`/v1/workbench/reasoning-timeline`, query), { credentials: 'same-origin' });
  },
  workspaceScan(query) {
    return fetch(withQuery(`/v1/workspace/scan`, query), { credentials: 'same-origin' });
  },
  workspaceStoryline(query) {
    return fetch(withQuery(`/v1/workspace/storyline`, query), { credentials: 'same-origin' });
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// CruxApiGated — the ONLY mutations the v2 console can perform.
//
// Every method below is BOTH:
//   * operator-posture UI-gated — pages/render/shell reach these only through
//     render.js operatorGatedCall(), which refuses unless CRUX_POSTURE==='operator';
//   * server-side auth-gated — the daemon enforces admin/facts scopes on each.
//
// Adding a mutation requires editing GATED_MUTATIONS in the generator
// (crates/corecruxd/tests/route_spec_drift.rs) — a reviewable diff + a regenerated
// api.js. Do NOT widen this list casually: the customer-safe posture depends on
// it staying tiny. The GATED_MUTATIONS array is the machine-readable twin the
// smoke audits against the methods below.
// ─────────────────────────────────────────────────────────────────────────────
const GATED_MUTATIONS = Object.freeze([
  Object.freeze(['POST', '/v1/work/gate/{actionId}/approve']),
  Object.freeze(['POST', '/v1/work/gate/{actionId}/reject']),
  Object.freeze(['POST', '/v1/work/{id}/comments']),
  Object.freeze(['POST', '/v1/actions/enrich']),
]);

const CruxApiGated = Object.freeze({
  gateApprove(actionId, body) {
    return fetch(`/v1/work/gate/${encodeURIComponent(actionId)}/approve`, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) });
  },
  gateReject(actionId, body) {
    return fetch(`/v1/work/gate/${encodeURIComponent(actionId)}/reject`, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) });
  },
  workComment(id, body) {
    return fetch(`/v1/work/${encodeURIComponent(id)}/comments`, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) });
  },
  actionsEnrich(body) {
    return fetch(`/v1/actions/enrich`, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) });
  },
});

// Classic-script globals for the no-build v2 console. No `export` — the
// console loads this with a plain <script src="/console-v2/api.js">.
if (typeof window !== 'undefined') {
  window.CruxApi = CruxApi;
  window.CruxApiGated = CruxApiGated;
  window.CRUX_GATED_MUTATIONS = GATED_MUTATIONS;
}
