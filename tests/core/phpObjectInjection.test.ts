import { describe, expect, it } from 'vitest';
import PhpObjectInjection from '../../source/core/static-analysis/tools/injection/phpObjectInjection';

const tool = new PhpObjectInjection();
const run = (value: unknown) => tool.run({ name: 'data', value, type: typeof value, location: 'body' } as never);
const rulesOf = (value: unknown) => (run(value).evidence as { rules: string[] } | undefined)?.rules ?? [];
const base64 = (text: string) => Buffer.from(text).toString('base64');

// PHPGGC Monolog/RCE1, trimmed
const MONOLOG = 'O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:9:"' + '\0*\0socket";O:29:"Monolog\\Handler\\BufferHandler":1:{s:10:"\0*\0handler";r:2;}}';

describe('php_object_injection', () => {
  it.each([
    ['plain object', 'O:8:"stdClass":1:{s:4:"exec";s:2:"id";}', ['serialized_object']],
    ['custom serialized object', 'C:11:"ArrayObject":21:{x:i:0;a:0:{};m:a:0:{}}', ['serialized_custom_object', 'builtin_gadget_class']],
    ['object nested in an array', 'a:1:{i:0;O:10:"SoapClient":0:{}}', ['serialized_object', 'builtin_gadget_class']],
    ['signed length', 'O:+8:"stdClass":0:{}', ['serialized_object', 'signed_length_bypass']],
    ['gadget chain with references', MONOLOG, ['serialized_object', 'gadget_chain_class', 'object_reference']],
    ['hex-escaped strings', 'O:8:"stdClass":1:{S:3:"cmd";S:6:"\\73ystem";}', ['serialized_object', 'escaped_string']],
    ['url-encoded object', encodeURIComponent('O:8:"stdClass":0:{}'), ['serialized_object']],
    ['base64 object', base64('O:8:"stdClass":0:{}'), ['serialized_object', 'base64_encoded']],
    ['base64 in a cookie-style value', `remember=${base64('a:1:{i:0;O:8:"stdClass":0:{}}')}`, ['serialized_object', 'base64_encoded']],
    ['serialized string escape', 'aaaa";s:8:"password";s:6:"hacked";}', ['serialized_string_breakout']],
    ['phar wrapper', 'phar://uploads/avatar.jpg/test.txt', ['phar_wrapper']],
    ['wrapped phar wrapper', 'compress.zlib://phar:///var/www/uploads/a.gif', ['phar_wrapper']],
  ])('flags a %s', (_, value, rules) => {
    expect(run(value).verdict).toBe('SUSPICIOUS');
    expect(rulesOf(value)).toEqual(expect.arrayContaining(rules));
  });

  it.each([
    ['plain text', 'Hello, my order number is 12345'],
    ['JSON', '{"name":"O:8","value":"stdClass"}'],
    ['serialized array of scalars', 'a:2:{i:0;s:5:"hello";s:3:"key";b:1;}'],
    ['header with a wrong length', 'O:9:"stdClass":0:{}'],
    ['CSS', '.a{content:"x";}'],
    ['a time', '10:30:"lunch"'],
    ['a number', 42],
    ['base64 that is not serialized data', base64('The quick brown fox jumps over the lazy dog')],
  ])('leaves %s alone', (_, value) => {
    expect(run(value).verdict).toBe('SAFE');
  });

  it('reports the class names it found', () => {
    expect(run(MONOLOG).evidence).toMatchObject({
      name: 'data',
      location: 'body',
      classes: ['Monolog\\Handler\\SyslogUdpHandler', 'Monolog\\Handler\\BufferHandler'],
    });
  });
});
