import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult } from '@tessera/core/static-analysis/shared';

// hard-coded until we have enough infrastructure to support tool configuration
// A small seed list of common English profanity. Extend it, or load a maintained list, for real use.
const TERMS = [
    'fuck', 'motherfucker', 'shit', 'bullshit', 'horseshit', 'shithead', 'dipshit', 'bitch', 'bastard',
    'asshole', 'arsehole', 'dumbass', 'jackass', 'dickhead', 'cunt', 'piss', 'wanker', 'twat',
    'douchebag', 'bollocks',
];

// Endings that still count as the term: fucking, fucker, shitty, bitches, pissed, ...
const SUFFIXES = ['s', 'es', 'ed', 'er', 'ers', 'ing', 'y'];

// Digit look-alikes, applied only inside words that also contain a letter ("sh1t", "a55h0le").
const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't' };

const MAX_MATCHES = 10;
const MAX_WORDS = 5000;

// "fuuuuck" -> "fuck", "bullshit" -> "bulshit". Applied to both the input and the terms, so repeated
// letters can't be used to dodge the list.
const collapse = (text: string): string => text.replace(/(.)\1+/g, '$1');

// collapsed term -> original term
const COLLAPSED_TERMS = new Map(TERMS.map(term => [collapse(term), term] as const));

// Whole-word match with an optional ending. Anchored on both sides, so words that merely contain a term
// ("Scunthorpe", "shiitake", "assassin") never match. No g flag, so .exec has no lastIndex state.
const WORD_PATTERN = new RegExp(`^(${[...COLLAPSED_TERMS.keys()].join('|')})(?:${SUFFIXES.join('|')})?$`);

// Every term with every ending, used for masked words such as "f*ck" and "sh*tty".
const MASKED_FORMS = TERMS.flatMap(term =>
    ['', ...SUFFIXES].map(suffix => ({ form: term + suffix, term })),
);

export default class ProfanityFilter extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'profanity_filter',
            displayName: 'Profanity filter',
            category: ToolCategory.Anomaly, // there is no content category yet, so this is the closest fit
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string') {
            return ProfanityFilter.safe(this.tool);
        }

        const words = ProfanityFilter.words(ProfanityFilter.normalize(context.value));
        const candidates = [...words, ...ProfanityFilter.joinSpacedLetters(words)];

        const matches = new Set<string>();
        for (const candidate of candidates) {
            const term = candidate.includes('*')
                ? ProfanityFilter.matchMasked(candidate)
                : ProfanityFilter.matchPlain(candidate);
            if (term) {
                matches.add(term);
            }
        }

        if (matches.size > 0) {
            return {
                tool: this.tool,
                status: 'SUCCESS',
                verdict: 'POLICY_VIOLATION',
                // list terms only, never the surrounding text
                evidence: {
                    name: String(context.name).slice(0, 100),
                    location: context.location,
                    matches: [...matches].slice(0, MAX_MATCHES),
                },
            };
        }

        return ProfanityFilter.safe(this.tool);
    }

    // Folds the text so look-alike spellings land on plain lowercase letters.
    private static normalize(value: string): string {
        return value
            .normalize('NFKD') // fullwidth letters become ASCII, accented letters split into base + mark
            .replace(/[\u0300-\u036f]/g, '') // drop the combining marks ("fúck" -> "fuck")
            .replace(/[\u00ad\u200b-\u200d\u2060\ufeff]/g, '') // drop invisible padding ("fu<zwsp>ck")
            .toLowerCase()
            // ! and + only between alphanumerics, so "shit!" keeps its exclamation mark
            .replace(/(?<=[a-z0-9])[!+](?=[a-z0-9])/g, symbol => (symbol === '!' ? 'i' : 't'))
            // @ and $ when a letter, digit or another @/$ follows ("@sshole", "a$$hole"), so "cost$" is untouched
            .replace(/[@$](?=[a-z0-9@$])/g, symbol => (symbol === '@' ? 'a' : 's'));
    }

    private static words(text: string): string[] {
        return text
            .split(/[^a-z0-9*]+/)
            .map(word => word.replace(/^\*+|\*+$/g, '')) // markdown emphasis like *word* is not a mask
            .filter(Boolean)
            .slice(0, MAX_WORDS)
            .map(word => (/[a-z]/.test(word) ? word.replace(/[013457]/g, digit => LEET[digit]) : word));
    }

    // "f u c k", "f.u.c.k", "s-h-i-t": runs of three or more single letters are joined into one word.
    private static joinSpacedLetters(words: string[]): string[] {
        const joined: string[] = [];
        let run = '';
        let count = 0;

        for (const word of [...words, '']) { // the empty sentinel flushes a run at the end
            if (word.length === 1 && /[a-z]/.test(word)) {
                run += word;
                count++;
            } else {
                if (count >= 3) {
                    joined.push(run);
                }
                run = '';
                count = 0;
            }
        }

        return joined;
    }

    private static matchPlain(word: string): string | undefined {
        const match = WORD_PATTERN.exec(collapse(word));
        return match ? COLLAPSED_TERMS.get(match[1]) : undefined;
    }

    // "f*ck": the * stands for any single character. Needs at least two real letters and one mask.
    private static matchMasked(word: string): string | undefined {
        const letters = word.replace(/\*/g, '').length;
        if (letters < 2 || letters === word.length) {
            return undefined;
        }

        return MASKED_FORMS.find(({ form }) =>
            form.length === word.length
            && [...word].every((char, index) => char === '*' || char === form[index]),
        )?.term;
    }

    private static safe(tool: string): ToolResult {
        return {
            tool,
            status: 'SUCCESS',
            verdict: 'SAFE',
            evidence: undefined,
        };
    }
}