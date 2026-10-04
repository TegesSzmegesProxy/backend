import { NormalizedRequest, ToolConfig } from '@tessera/shared/contracts';
import {
    ExpiringMap, Tool, ToolCategory, ToolContextType, ToolResult, ToolState, accountOf, hashOf, lookupCidr, safe, suspicious,
} from '@tessera/core/static-analysis/shared';

interface Sighting {
    at: number;
    lat: number;
    lon: number;
    city: string;
    country: string;
}

export default class ImpossibleTravel extends Tool<ToolContextType.Full> {
    // (Redis, per tenant) account -> last located sighting.
    private readonly lastSeen: ExpiringMap<Sighting>;

    constructor(private readonly config: ToolConfig<'impossible_travel'>, state: ToolState) {
        super({
            id: 'impossible_travel',
            displayName: 'Impossible travel',
            category: ToolCategory.Auth,
            contextType: ToolContextType.Full,
        });
        this.lastSeen = state.expiring<Sighting>('lastSeen', config.memoryMs);
    }

    override async run(context: NormalizedRequest): Promise<ToolResult> {
        const account = accountOf(context);
        const location = lookupCidr(context.clientIp, this.config.geoIp);
        if (!account || !location) {
            return safe(this.tool); // anonymous, or an address the geo database can't place
        }

        const now = typeof context.timestamp === 'number' ? context.timestamp : Date.now();
        const key = hashOf(account);
        const current: Sighting = { at: now, lat: location.lat, lon: location.lon, city: location.city, country: location.country };
        const previous = await this.lastSeen.get(context.tenantId, key);
        await this.lastSeen.set(context.tenantId, key, current);

        if (!previous) {
            return safe(this.tool);
        }

        const distanceKm = ImpossibleTravel.haversineKm(previous, current);
        if (distanceKm < this.config.minDistanceKm) {
            return safe(this.tool);
        }

        const hours = Math.max((now - previous.at) / 3_600_000, 1 / 3600); // at least one second
        const speedKmh = distanceKm / hours;
        if (speedKmh > this.config.maxSpeedKmh) {
            return suspicious(this.tool, {
                from: `${previous.city}, ${previous.country}`,
                to: `${current.city}, ${current.country}`,
                distanceKm: Math.round(distanceKm),
                minutesApart: Math.round((now - previous.at) / 60_000),
                speedKmh: Math.round(speedKmh),
            });
        }
        return safe(this.tool);
    }

    private static haversineKm(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
        const radians = (degrees: number): number => (degrees * Math.PI) / 180;
        const dLat = radians(b.lat - a.lat);
        const dLon = radians(b.lon - a.lon);
        const h = Math.sin(dLat / 2) ** 2 + Math.cos(radians(a.lat)) * Math.cos(radians(b.lat)) * Math.sin(dLon / 2) ** 2;
        return 2 * 6371 * Math.asin(Math.sqrt(h));
    }
}
