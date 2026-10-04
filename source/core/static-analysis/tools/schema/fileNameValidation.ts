import { RequestFile, ToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, safe, violation } from '@tessera/core/static-analysis/shared';

// Device names Windows resolves anywhere in a path, with any extension ("CON.txt" is still the console).
const RESERVED_NAMES = /^(?:con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$|clock\$)$/i;

const RULES: { name: string; test: (filename: string, maxLength: number) => boolean }[] = [
    { name: 'empty', test: filename => filename.trim() === '' },
    { name: 'too_long', test: (filename, maxLength) => filename.length > maxLength },
    { name: 'control_characters', test: filename => /[\u0000-\u001f\u007f-\u009f]/.test(filename) },
    { name: 'path_separator', test: filename => /[/\\]/.test(filename) },
    { name: 'dot_segment', test: filename => /^\.{1,2}$/.test(filename) },
    { name: 'reserved_windows_name', test: filename => RESERVED_NAMES.test(filename.split('.')[0].trim()) },
    { name: 'trailing_dot_or_space', test: filename => /[.\s]$/.test(filename) },
    { name: 'leading_space', test: filename => /^\s/.test(filename) },
    // < > : " | ? * are invalid on Windows; ":" also opens an alternate data stream (file.php::$DATA)
    { name: 'forbidden_characters', test: filename => /[<>:"|?*]/.test(filename) },
    { name: 'bidi_or_invisible_characters', test: filename => /[​-‏‪-‮⁦-⁩﻿]/.test(filename) },
];

export default class FileNameValidation extends Tool<ToolContextType.File> {
    constructor(private readonly config: ToolConfig<'file_name_validation'>) {
        super({
            id: 'file_name_validation',
            displayName: 'File name validation',
            category: ToolCategory.Schema,
            contextType: ToolContextType.File,
        });
    }

    override run(context: RequestFile): ToolResult {
        const filename = typeof context.filename === 'string' ? context.filename : '';
        const matched = RULES.filter(rule => rule.test(filename, this.config.maxLength)).map(rule => rule.name);

        return matched.length > 0
            ? violation(this.tool, { filename: JSON.stringify(clip(filename, 100)), field: clip(context.field, 50), rules: matched })
            : safe(this.tool);
    }
}
