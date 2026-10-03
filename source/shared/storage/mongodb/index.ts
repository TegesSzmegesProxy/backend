import { MongoClient, type Db } from "mongodb";
import { mongoDbName, mongoUrl } from "../../config";
import { assertTenantId } from "../tenant-id";

type MongoStorageOptions = {
  url?: string;
  dbName?: string;
};

class MongoStorage {
  private readonly client: MongoClient;
  private readonly dbName: string;
  private connecting: Promise<MongoClient> | undefined;

  constructor({ url = mongoUrl(), dbName = mongoDbName() }: MongoStorageOptions = {}) {
    this.client = new MongoClient(url);
    this.dbName = dbName;
  }

  /** Connects once; later and concurrent calls reuse the existing connection. */
  async connect(): Promise<void> {
    this.connecting ??= this.client.connect();
    try {
      await this.connecting;
    } catch (error) {
      // Allow a later call to retry instead of reusing a failed attempt.
      this.connecting = undefined;
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    this.connecting = undefined;
    await this.client.close();
  }

  /** Platform database (e.g. the tenant registry). Tenant data never lives here. */
  get db(): Db {
    return this.client.db(this.dbName);
  }

  /**
   * Each tenant has its own database, so isolation comes from the database boundary rather
   * than from per-query filters. MongoDB creates the database lazily on first write.
   */
  tenantDb(tenantId: string): Db {
    return this.client.db(`${this.dbName}_t_${assertTenantId(tenantId)}`);
  }

  /** Ids of all tenants that have a database, e.g. to load their policies on startup. */
  async listTenantIds(): Promise<string[]> {
    const prefix = `${this.dbName}_t_`;
    const { databases } = await this.client.db().admin().listDatabases({ nameOnly: true });
    return databases.flatMap(({ name }) => (name.startsWith(prefix) ? [name.slice(prefix.length)] : []));
  }
}

export { MongoStorage };
export type { MongoStorageOptions };
