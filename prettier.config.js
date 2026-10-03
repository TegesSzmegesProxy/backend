export default {
    semi: true,
    singleQuote: true,
    tabWidth: 4,
    trailingComma: 'es5',
    quoteProps: 'as-needed',
    bracketSpacing: true,
    arrowParens: 'avoid',
    overrides: [
        {
            files: '*.json',
            options: {
                tabWidth: 2,
            },
        },
    ],
};