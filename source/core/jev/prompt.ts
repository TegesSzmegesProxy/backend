import { noul, score } from '@typesafe-ai/sdk';

/**
 * The enforcement question. Its P(yes) is the attack probability the thresholds compare against.
 * The wording describes what a value would do when the application uses it, never which words it contains,
 * so it generalizes instead of encoding individual requests.
 */
export const JEV_ATTACK_QUESTION = noul(
    'Is this request an attack attempt? Judge each field value by what it would do when the endpoint uses it as intended, not by the words or characters it contains. patternMatches come from a keyword and regex pre-filter that fires on ordinary text; verify each against the actual value.',
    {
        true: 'At least one value contains syntax that would change how the application interprets it: breaking out of a quoted string or literal, injecting query clauses, statements, markup, script, template expressions, shell commands, path segments, or URLs pointing at internal hosts, or an object or array of query operators where a plain value is expected. Or the request explicitly abuses the endpoint or the caller\'s authorization. This holds whether or not the attack would succeed.',
        false: 'Every value is plausible input for this endpoint, including names, free text, secrets such as passwords that are compared or hashed rather than interpreted, or content that merely contains programming keywords, punctuation, or special characters without forming syntax that would change how the application interprets it. A pattern match on such a value is not evidence of an attack.',
    }
);

/** Severity for display and logging only; enforcement uses JEV_ATTACK_QUESTION. */
export const JEV_SEVERITY_QUESTION = score('How severe is the security risk of this request?', [
    'Benign: ordinary input for this endpoint.',
    'Anomalous: unusual input or probing, without syntax that would change how the application interprets it.',
    'Attack attempt: a value carries injection, traversal, SSRF, or authorization abuse, whether or not it would succeed.',
    'Critical: an attack attempt with evidence it can succeed or is part of an escalating sequence.',
]);
