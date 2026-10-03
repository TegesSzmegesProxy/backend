import { createClient } from "redis";
import { redisUrl } from "../config";

type MessageHandler = (message: string, channel: string) => void | Promise<void>;

type BrokerOptions = {
  url?: string;
};

class Broker {
  private readonly publisher;
  private readonly subscriber;

  constructor({ url = redisUrl() }: BrokerOptions = {}) {
    this.publisher = createClient({ url });
    this.subscriber = this.publisher.duplicate();

    // An unhandled "error" event would crash the process. node-redis reconnects by itself
    // and re-subscribes to all active channels once the connection is back.
    this.publisher.on("error", (error) => console.error("[broker] publisher error:", error));
    this.subscriber.on("error", (error) => console.error("[broker] subscriber error:", error));
  }

  async connect(): Promise<void> {
    await Promise.all([
      this.publisher.isOpen ? undefined : this.publisher.connect(),
      this.subscriber.isOpen ? undefined : this.subscriber.connect(),
    ]);
  }

  async disconnect(): Promise<void> {
    await Promise.all([
      this.publisher.isOpen ? this.publisher.close() : undefined,
      this.subscriber.isOpen ? this.subscriber.close() : undefined,
    ]);
  }

  /** Publishes `message` to `channel`. Resolves with the number of receivers. */
  async publish(channel: string, message: string): Promise<number> {
    return this.publisher.publish(channel, message);
  }

  /** Subscribes `handler` to `channel`. Returns a function that removes the subscription. */
  async subscribe(channel: string, handler: MessageHandler): Promise<() => Promise<void>> {
    const safeHandler = this.guard(channel, handler);
    await this.subscriber.subscribe(channel, safeHandler);
    return async () => {
      await this.subscriber.unsubscribe(channel, safeHandler);
    };
  }

  /** Same as `subscribe`, but matches channels with a glob pattern, e.g. `policy.*`. */
  async psubscribe(pattern: string, handler: MessageHandler): Promise<() => Promise<void>> {
    const safeHandler = this.guard(pattern, handler);
    await this.subscriber.pSubscribe(pattern, safeHandler);
    return async () => {
      await this.subscriber.pUnsubscribe(pattern, safeHandler);
    };
  }

  // A throwing handler must not become an unhandled rejection.
  private guard(target: string, handler: MessageHandler): MessageHandler {
    return async (message, channel) => {
      try {
        await handler(message, channel);
      } catch (error) {
        console.error(`[broker] handler for "${target}" failed:`, error);
      }
    };
  }
}

export { Broker };
export type { MessageHandler, BrokerOptions };
