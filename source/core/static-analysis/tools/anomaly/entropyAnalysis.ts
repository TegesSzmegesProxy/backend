import { RequestField, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, fieldLeaf, safe, suspicious } from '@tessera/core/static-analysis/shared';

const MAX_LENGTH = 8192;

// config.thresholds: bits per character above which a value looks random rather than written by a person.
// English prose sits around 4.0-4.4; random hex tops out at 4.0, random base64 around 5.5-6.0.

export default class EntropyAnalysis extends Tool<ToolContextType.Field> {
    // fields that are supposed to be random, so high entropy there is expected
    private readonly randomFields: ReadonlySet<string>;

    constructor(private readonly config: ToolConfig<'entropy_analysis'>) {
        super({
            id: 'entropy_analysis',
            displayName: 'Entropy analysis',
            category: ToolCategory.Anomaly,
            contextType: ToolContextType.Field,
        });
        this.randomFields = new Set(config.randomFields);
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string' || this.randomFields.has(fieldLeaf(context.name))) {
            return safe(this.tool);
        }

        const value = context.value.slice(0, MAX_LENGTH);
        // whitespace-separated prose is never random enough to matter; the longest word is where a blob hides
        const longest = value.split(/\s+/).reduce((best, word) => (word.length > best.length ? word : best), '');
        if (longest.length < this.config.minLength) {
            return safe(this.tool);
        }

        const charset = /^[0-9a-f]+$/i.test(longest) ? 'hex' : /^[A-Za-z0-9+/=_-]+$/.test(longest) ? 'base64' : 'mixed';
        const entropy = EntropyAnalysis.shannon(longest);

        const threshold = this.config.thresholds[charset];
        if (entropy >= threshold) {
            return suspicious(this.tool, {
                name: clip(context.name),
                location: context.location,
                charset,
                entropy: Math.round(entropy * 100) / 100,
                threshold,
                length: longest.length,
            });
        }

        return safe(this.tool);
    }

    // Shannon entropy in bits per character.
    private static shannon(text: string): number {
        const counts = new Map<string, number>();
        for (const char of text) {
            counts.set(char, (counts.get(char) ?? 0) + 1);
        }
        let entropy = 0;
        for (const count of counts.values()) {
            const p = count / text.length;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }
}
