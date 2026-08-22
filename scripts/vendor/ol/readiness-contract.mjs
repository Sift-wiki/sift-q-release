// Vendored verifier from Sift-wiki/sift-q-refactor@4647c4cc8cd665f91385fcf248219c27c99870a9.
// This checked-in public copy is release authority; candidate source may not replace it.
import { createHash } from "node:crypto";

export const READINESS_RECEIPT_SCHEMA = "ol-dev-prod-readiness/v2";
export const EVIDENCE_RECORD_SCHEMA = "ol-dev-prod-evidence/v2";
export const EVIDENCE_SET_SCHEMA = "ol-dev-prod-evidence-set/v2";

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/;
const REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const ENVIRONMENT_KEYS = [
  "credentialPrincipal",
  "environmentId",
  "mutationAuthority",
  "stateAuthority",
];
const AUTHORITY_KEYS = ["authorityId", "evidenceDigest", "identityType"];
const CREDENTIAL_KEYS = ["evidenceDigest", "identityType", "principalId"];
const EVIDENCE_KEYS = [
  "authorityKind",
  "capturedAt",
  "environmentId",
  "kind",
  "observationDigest",
  "result",
  "schemaVersion",
  "subjectId",
  "targetEnvironmentId",
];
const NEGATIVE_KEYS = [
  "authorityKind",
  "evidenceDigest",
  "fromEnvironmentId",
  "result",
  "toEnvironmentId",
];
const PAYLOAD_KEYS = [
  "development",
  "evidenceSetDigest",
  "expiresAt",
  "issuedAt",
  "negativeIsolation",
  "policyDigest",
  "production",
  "purpose",
  "repository",
  "result",
  "schemaVersion",
  "selectedSha",
];
const AUTHORITY_KINDS = ["credential", "mutation", "state"];

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactKeys(value, expected, label) {
  invariant(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${label} is invalid`,
  );
  invariant(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(expected),
    `${label} keys drift`,
  );
}

function assertIdentifier(value, label) {
  invariant(
    typeof value === "string" && IDENTIFIER.test(value),
    `${label} is invalid`,
  );
  return value;
}

function parseTime(value, label) {
  invariant(typeof value === "string", `${label} is missing`);
  const milliseconds = Date.parse(value);
  invariant(
    Number.isFinite(milliseconds) &&
      new Date(milliseconds).toISOString() === value,
    `${label} is invalid`,
  );
  return milliseconds;
}

function canonicalValue(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    invariant(
      Number.isFinite(value),
      "signed JSON contains a non-finite number",
    );
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(",")}]`;
  invariant(
    typeof value === "object",
    "signed JSON contains an unsupported value",
  );
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalValue(value[key])}`)
    .join(",")}}`;
}

export function canonicalJson(value) {
  return canonicalValue(value);
}

export function sha256Digest(value) {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function validateEvidenceRecord(record) {
  assertExactKeys(record, EVIDENCE_KEYS, "OL readiness evidence record");
  invariant(
    record.schemaVersion === EVIDENCE_RECORD_SCHEMA,
    "OL evidence schema drift",
  );
  invariant(
    record.kind === "authority-binding" || record.kind === "negative-isolation",
    "OL evidence kind is invalid",
  );
  invariant(
    AUTHORITY_KINDS.includes(record.authorityKind),
    "OL evidence authority kind is invalid",
  );
  assertIdentifier(record.environmentId, "OL evidence environment ID");
  assertIdentifier(record.subjectId, "OL evidence subject ID");
  invariant(
    SHA256.test(record.observationDigest),
    "OL evidence observation digest is invalid",
  );
  parseTime(record.capturedAt, "OL evidence capturedAt");
  if (record.kind === "authority-binding") {
    invariant(
      record.targetEnvironmentId === null,
      "OL binding evidence has a target environment",
    );
    invariant(record.result === "bound", "OL binding evidence did not bind");
  } else {
    assertIdentifier(
      record.targetEnvironmentId,
      "OL isolation target environment ID",
    );
    invariant(
      record.targetEnvironmentId !== record.environmentId,
      "OL isolation evidence targets its source environment",
    );
    invariant(
      record.result === "denied",
      "OL negative isolation evidence did not deny access",
    );
  }
  return record;
}

function validateAuthority(value, label) {
  assertExactKeys(value, AUTHORITY_KEYS, label);
  invariant(value.identityType === "nonhuman", `${label} is not nonhuman`);
  invariant(
    SHA256.test(value.evidenceDigest),
    `${label} evidence digest is invalid`,
  );
  return {
    authorityId: assertIdentifier(value.authorityId, `${label} ID`),
    evidenceDigest: value.evidenceDigest,
  };
}

function validateEnvironment(value, label) {
  assertExactKeys(value, ENVIRONMENT_KEYS, `${label} environment`);
  assertExactKeys(
    value.credentialPrincipal,
    CREDENTIAL_KEYS,
    `${label} credential principal`,
  );
  invariant(
    value.credentialPrincipal.identityType === "nonhuman",
    `${label} credential principal is not nonhuman`,
  );
  invariant(
    SHA256.test(value.credentialPrincipal.evidenceDigest),
    `${label} credential evidence digest is invalid`,
  );
  return {
    environmentId: assertIdentifier(
      value.environmentId,
      `${label} environment ID`,
    ),
    credential: {
      authorityId: assertIdentifier(
        value.credentialPrincipal.principalId,
        `${label} credential principal ID`,
      ),
      evidenceDigest: value.credentialPrincipal.evidenceDigest,
    },
    mutation: validateAuthority(
      value.mutationAuthority,
      `${label} mutation authority`,
    ),
    state: validateAuthority(value.stateAuthority, `${label} state authority`),
  };
}

function evidenceRecordFor(records, digest, expected, label) {
  const record = records.get(digest);
  invariant(record !== undefined, `${label} evidence is missing`);
  for (const [key, value] of Object.entries(expected)) {
    invariant(record[key] === value, `${label} evidence does not match ${key}`);
  }
}

function validateEnvironmentEvidence(records, environment, label) {
  for (const authorityKind of AUTHORITY_KINDS) {
    const authority = environment[authorityKind];
    evidenceRecordFor(
      records,
      authority.evidenceDigest,
      {
        kind: "authority-binding",
        authorityKind,
        environmentId: environment.environmentId,
        subjectId: authority.authorityId,
        targetEnvironmentId: null,
        result: "bound",
      },
      `${label} ${authorityKind} binding`,
    );
  }
}

function expectedIsolationPairs(developmentId, productionId) {
  return [
    ...AUTHORITY_KINDS.map((authorityKind) => ({
      authorityKind,
      fromEnvironmentId: developmentId,
      toEnvironmentId: productionId,
    })),
    ...AUTHORITY_KINDS.map((authorityKind) => ({
      authorityKind,
      fromEnvironmentId: productionId,
      toEnvironmentId: developmentId,
    })),
  ];
}

function isolationKey(value) {
  return `${value.fromEnvironmentId}->${value.toEnvironmentId}:${value.authorityKind}`;
}

function validateNegativeIsolation(entries, records, development, production) {
  invariant(
    Array.isArray(entries),
    "OL negative isolation results are invalid",
  );
  const expected = expectedIsolationPairs(
    development.environmentId,
    production.environmentId,
  );
  invariant(
    entries.length === expected.length,
    "OL negative isolation result count drift",
  );
  const actualByKey = new Map();
  for (const entry of entries) {
    assertExactKeys(entry, NEGATIVE_KEYS, "OL negative isolation result");
    invariant(
      AUTHORITY_KINDS.includes(entry.authorityKind),
      "OL isolation authority kind is invalid",
    );
    assertIdentifier(
      entry.fromEnvironmentId,
      "OL isolation source environment ID",
    );
    assertIdentifier(
      entry.toEnvironmentId,
      "OL isolation target environment ID",
    );
    invariant(
      entry.result === "denied",
      "OL negative isolation result did not deny access",
    );
    invariant(
      SHA256.test(entry.evidenceDigest),
      "OL isolation evidence digest is invalid",
    );
    const key = isolationKey(entry);
    invariant(
      !actualByKey.has(key),
      "OL negative isolation result is duplicated",
    );
    actualByKey.set(key, entry);
  }
  for (const pair of expected) {
    const key = isolationKey(pair);
    const entry = actualByKey.get(key);
    invariant(
      entry !== undefined,
      `OL negative isolation result ${key} is missing`,
    );
    const source =
      pair.fromEnvironmentId === development.environmentId
        ? development
        : production;
    evidenceRecordFor(
      records,
      entry.evidenceDigest,
      {
        kind: "negative-isolation",
        authorityKind: pair.authorityKind,
        environmentId: pair.fromEnvironmentId,
        subjectId: source[pair.authorityKind].authorityId,
        targetEnvironmentId: pair.toEnvironmentId,
        result: "denied",
      },
      `OL negative isolation ${key}`,
    );
  }
}

function evidenceMap(evidenceRecords) {
  invariant(
    Array.isArray(evidenceRecords),
    "OL readiness evidence bundle is missing",
  );
  invariant(
    evidenceRecords.length > 0 && evidenceRecords.length <= 64,
    "OL evidence count is invalid",
  );
  const records = new Map();
  for (const record of evidenceRecords) {
    validateEvidenceRecord(record);
    const digest = sha256Digest(record);
    invariant(
      !records.has(digest),
      "OL readiness evidence record is duplicated",
    );
    records.set(digest, record);
  }
  return records;
}

export function evidenceSetDigest(evidenceRecords) {
  const records = evidenceMap(evidenceRecords);
  return sha256Digest({
    schemaVersion: EVIDENCE_SET_SCHEMA,
    digests: [...records.keys()].sort(),
  });
}

export function validateReadinessPayload({
  payload,
  evidenceRecords,
  trustPolicy,
  maximumReceiptLifetimeSeconds,
  clockSkewSeconds,
  now,
}) {
  assertExactKeys(payload, PAYLOAD_KEYS, "OL readiness receipt");
  invariant(
    payload.schemaVersion === READINESS_RECEIPT_SCHEMA,
    "OL readiness receipt schema drift",
  );
  invariant(
    payload.purpose === "ol-activation",
    "OL readiness receipt purpose drift",
  );
  invariant(payload.result === "passed", "OL readiness receipt did not pass");
  invariant(
    REPOSITORY.test(payload.repository),
    "OL readiness repository is invalid",
  );
  invariant(
    GIT_SHA.test(payload.selectedSha),
    "OL readiness selected SHA is invalid",
  );
  invariant(
    SHA256.test(payload.policyDigest),
    "OL readiness policy digest is invalid",
  );
  invariant(
    SHA256.test(payload.evidenceSetDigest),
    "OL evidence-set digest is invalid",
  );
  invariant(
    payload.repository === trustPolicy.repository,
    "OL readiness repository drift",
  );
  invariant(
    payload.selectedSha === trustPolicy.expectedSelectedSha,
    "OL readiness selected SHA drift",
  );
  invariant(
    payload.policyDigest === trustPolicy.policyDigest,
    "OL readiness policy drift",
  );

  const development = validateEnvironment(payload.development, "development");
  const production = validateEnvironment(payload.production, "production");
  invariant(
    development.environmentId === trustPolicy.developmentEnvironmentId,
    "OL development environment identity drift",
  );
  invariant(
    production.environmentId === trustPolicy.productionEnvironmentId,
    "OL production environment identity drift",
  );
  invariant(
    development.environmentId !== production.environmentId,
    "OL development and production environment identities are not separate",
  );
  for (const authorityKind of AUTHORITY_KINDS) {
    invariant(
      development[authorityKind].authorityId !==
        production[authorityKind].authorityId,
      `OL development and production ${authorityKind} authorities are not separate`,
    );
  }

  const issuedAt = parseTime(payload.issuedAt, "OL readiness receipt issuedAt");
  const expiresAt = parseTime(
    payload.expiresAt,
    "OL readiness receipt expiresAt",
  );
  const lifetime = expiresAt - issuedAt;
  invariant(lifetime > 0, "OL readiness receipt lifetime is invalid");
  invariant(
    lifetime <= maximumReceiptLifetimeSeconds * 1000,
    "OL readiness receipt lifetime is too long",
  );
  const skew = clockSkewSeconds * 1000;
  invariant(issuedAt <= now + skew, "OL readiness receipt is not active yet");
  invariant(expiresAt >= now - skew, "OL readiness receipt expired");

  const records = evidenceMap(evidenceRecords);
  for (const record of records.values()) {
    const capturedAt = parseTime(record.capturedAt, "OL evidence capturedAt");
    invariant(
      capturedAt <= issuedAt + skew,
      "OL readiness evidence was captured after issuance",
    );
    invariant(
      capturedAt >= issuedAt - maximumReceiptLifetimeSeconds * 1000,
      "OL readiness evidence is stale",
    );
  }
  invariant(
    payload.evidenceSetDigest === evidenceSetDigest(evidenceRecords),
    "OL evidence-set digest drift",
  );
  validateEnvironmentEvidence(records, development, "development");
  validateEnvironmentEvidence(records, production, "production");
  validateNegativeIsolation(
    payload.negativeIsolation,
    records,
    development,
    production,
  );
  const referenced = new Set([
    ...AUTHORITY_KINDS.flatMap((kind) => [
      development[kind].evidenceDigest,
      production[kind].evidenceDigest,
    ]),
    ...payload.negativeIsolation.map((entry) => entry.evidenceDigest),
  ]);
  invariant(
    referenced.size === records.size,
    "OL evidence bundle contains unreferenced evidence",
  );

  return payload;
}
