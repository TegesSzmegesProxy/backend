import { RequestField } from '@tessera/shared/contracts';
import { Tool, ToolCategory, ToolContextType, ToolResult, clip, decodeLayers, safe, suspicious } from '@tessera/core/static-analysis/shared';

const MAX_LENGTH = 16_384;
const MAX_BLOBS = 10;
const MAX_CLASSES = 5;

// O:8:"stdClass":1:{   C:11:"ArrayObject":21:{   O:+8:"stdClass"   (a "+" before the length slips past O:\d+ filters
// and PHP < 7.2 still accepts it). g flag: always used through matchAll, which copies the regex.
const OBJECT_HEADER = /([OC]):(\+?)(\d{1,4}):"([^"]{0,512})":\+?\d{1,6}:\{/g;

// S:4:"\73ystem" is a string whose \xx hex escapes PHP unpacks, used to hide gadget property values.
const ESCAPED_STRING = /(?:^|[;{])S:\d+:"[^"]*\\[0-9a-f]{2}/i;

// r:2; R:3; wire one object into another; chains need them to reach a sink (and for fast-destruct).
const REFERENCE = /[;{][rR]:\d+;/;

// ";s:8:"password";s:5:"admin";}  closes a serialized string the application built around user input and
// appends properties of its own (serialized string escape, after a filter changed the string's length).
// Well-formed serialized data is full of ";s: as well, so it only counts in text that does not start as such.
const STRING_BREAKOUT = /";(?:s:\d+:"|i:-?\d+;|b:[01];|[aOC]:\+?\d+:)/;
const SERIALIZED_START = /^\s*(?:[aOCsSidb]:|N;)/;

// phar://upload.jpg/x makes file functions (file_exists, getimagesize, fopen...) unserialize the archive's
// metadata, so it injects objects without unserialize() ever touching request data.
const PHAR_WRAPPER = /\bphar:\/\//i;

// base64 of O: / C: / a: (Tz / Qz / YT), the usual way serialized data rides in cookies and hidden fields.
const BASE64_SERIALIZED = /(?:^|[^A-Za-z0-9+/_-])((?:Tz|Qz|YT)[A-Za-z0-9+/_-]{14,}={0,2})(?![A-Za-z0-9+/=_-])/g;

// Namespaces of libraries with published gadget chains (PHPGGC). PHP class names are case-insensitive.
const GADGET_LIBRARY = /^\\?(?:Monolog|GuzzleHttp|Illuminate|Laravel|Symfony|Doctrine|Laminas|Zend|Faker|yii|think|CodeIgniter|Drupal|Magento|Slim|Phalcon|Pimple|Predis|phpseclib|Smarty|WpOrg\\Requests)\\|^(?:Swift_|Zend_|Mage_|Requests_|Smarty_)/i;

// Built-in classes that reach the filesystem or network, or have had memory-safety bugs on unserialize.
const BUILTIN_GADGETS: ReadonlySet<string> = new Set([
    'soapclient', 'splfileobject', 'spltempfileobject', 'directoryiterator', 'filesystemiterator',
    'recursivedirectoryiterator', 'globiterator', 'simplexmlelement', 'ziparchive',
    'arrayobject', 'splobjectstorage', 'spldoublylinkedlist',
]);

export default class PhpObjectInjection extends Tool<ToolContextType.Field> {
    constructor() {
        super({
            id: 'php_object_injection',
            displayName: 'PHP object injection',
            category: ToolCategory.Injection,
            contextType: ToolContextType.Field,
        });
    }

    override run(context: RequestField): ToolResult {
        if (typeof context.value !== 'string' || !/[:"]|%3a|%22|Tz|Qz|YT/i.test(context.value)) {
            return safe(this.tool);
        }

        const rules = new Set<string>();
        const classes = new Set<string>();

        for (const layer of decodeLayers(context.value.slice(0, MAX_LENGTH))) {
            PhpObjectInjection.scan(layer, rules, classes);
            for (const match of [...layer.matchAll(BASE64_SERIALIZED)].slice(0, MAX_BLOBS)) {
                const decoded = Buffer.from(match[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
                const before = rules.size + classes.size;
                PhpObjectInjection.scan(decoded, rules, classes);
                if (rules.size + classes.size > before) rules.add('base64_encoded');
            }
        }

        if (rules.size === 0) {
            return safe(this.tool);
        }
        return suspicious(this.tool, {
            name: clip(context.name),
            location: context.location,
            rules: [...rules],
            classes: classes.size > 0 ? [...classes].slice(0, MAX_CLASSES).map(name => clip(name, 64)) : undefined,
        });
    }

    private static scan(text: string, rules: Set<string>, classes: Set<string>): void {
        let objects = false;
        for (const [, kind, sign, length, name] of text.matchAll(OBJECT_HEADER)) {
            // PHP refuses a header whose length is not the class name's byte length, so a mismatch is not a payload
            if (Number(length) !== Buffer.byteLength(name, 'utf8') || !/^\\?[A-Za-z_\x80-\uffff][\w\x80-\uffff\\]*$/.test(name)) {
                continue;
            }
            objects = true;
            classes.add(name);
            rules.add(kind === 'C' ? 'serialized_custom_object' : 'serialized_object');
            if (sign) rules.add('signed_length_bypass');
            if (GADGET_LIBRARY.test(name)) rules.add('gadget_chain_class');
            if (BUILTIN_GADGETS.has(name.replace(/^\\/, '').toLowerCase())) rules.add('builtin_gadget_class');
        }

        if (objects && ESCAPED_STRING.test(text)) rules.add('escaped_string');
        if (objects && REFERENCE.test(text)) rules.add('object_reference');
        if (!SERIALIZED_START.test(text) && STRING_BREAKOUT.test(text)) rules.add('serialized_string_breakout');
        if (PHAR_WRAPPER.test(text)) rules.add('phar_wrapper');
    }
}
