// Dashboard-issued ObjectIds are safe, unambiguous Redis key prefix components.
const TENANT_ID_PATTERN = /^[0-9a-f]{24}$/;

function assertTenantId(tenantId: string): string {
  if (!TENANT_ID_PATTERN.test(tenantId)) {
    throw new Error("Invalid tenantId: expected MongoDB ObjectId");
  }
  return tenantId;
}

export { assertTenantId };
