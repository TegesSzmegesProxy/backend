// Tenant ids end up in MongoDB database names and Redis key prefixes. Restricting them to this
// alphabet keeps both namespaces unambiguous: no `:` to escape a Redis prefix and none of the
// characters MongoDB forbids in database names (`/\. "$*<>:|?`).
const TENANT_ID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;

function assertTenantId(tenantId: string): string {
  if (!TENANT_ID_PATTERN.test(tenantId)) {
    throw new Error("Invalid tenantId: expected uuid");
  }
  return tenantId;
}

export { assertTenantId };
