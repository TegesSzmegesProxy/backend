import type {
  Collection,
  Db,
  Document,
  Filter,
  OptionalUnlessRequiredId,
  UpdateFilter,
  WithId,
} from "mongodb";

/**
 * Generic collection access. It is handed a database connection and knows nothing about which
 * database that is: tenant isolation comes from passing `mongo.tenantDb(tenantId)`, so one
 * repository instance serves exactly one tenant. Subclass it to add domain-specific queries.
 */
class MongoRepository<T extends Document> {
  protected readonly collection: Collection<T>;

  constructor(db: Db, collectionName: string) {
    this.collection = db.collection<T>(collectionName);
  }

  findOne(filter: Filter<T>): Promise<WithId<T> | null> {
    return this.collection.findOne(filter);
  }

  find(filter: Filter<T> = {}, options: { limit?: number; skip?: number } = {}): Promise<WithId<T>[]> {
    return this.collection.find(filter, options).toArray();
  }

  async exists(filter: Filter<T>): Promise<boolean> {
    return (await this.collection.countDocuments(filter, { limit: 1 })) > 0;
  }

  count(filter: Filter<T> = {}): Promise<number> {
    return this.collection.countDocuments(filter);
  }

  /** Inserts a document and returns it with its generated `_id`. */
  async add(document: OptionalUnlessRequiredId<T>): Promise<WithId<T>> {
    const { insertedId } = await this.collection.insertOne(document);
    return { ...document, _id: insertedId } as unknown as WithId<T>;
  }

  /** Updates the first match. Returns false when nothing matched. */
  async update(filter: Filter<T>, update: UpdateFilter<T>): Promise<boolean> {
    const { matchedCount } = await this.collection.updateOne(filter, update);
    return matchedCount > 0;
  }

  /** Updates the first match, inserting a new document when none exists. */
  async upsert(filter: Filter<T>, update: UpdateFilter<T>): Promise<void> {
    await this.collection.updateOne(filter, update, { upsert: true });
  }

  /** Deletes the first match. Returns false when nothing matched. */
  async delete(filter: Filter<T>): Promise<boolean> {
    const { deletedCount } = await this.collection.deleteOne(filter);
    return deletedCount > 0;
  }

  /** Deletes every match and returns how many documents were removed. */
  async deleteMany(filter: Filter<T>): Promise<number> {
    const { deletedCount } = await this.collection.deleteMany(filter);
    return deletedCount;
  }
}

export { MongoRepository };
