import { type ToolConfig, type ToolId, parseToolConfig } from '@tessera/shared/contracts';
import { Tool, ToolContextType, ToolState } from '@tessera/core/static-analysis/shared';
import BusinessLogicTampering from './anomaly/businessLogicTampering';
import ContentTypeMismatch from './anomaly/contentTypeMismatch';
import DoubleEncoding from './anomaly/doubleEncoding';
import DuplicateRequest from './anomaly/duplicateRequest';
import EncodedPayload from './anomaly/encodedPayload';
import EntropyAnalysis from './anomaly/entropyAnalysis';
import HoneypotEndpoint from './anomaly/honeypotEndpoint';
import HoneypotField from './anomaly/honeypotField';
import MassAssignment from './anomaly/massAssignment';
import MethodAnomaly from './anomaly/methodAnomaly';
import MethodOverride from './anomaly/methodOverride';
import OverlongUtf8 from './anomaly/overlongUtf8';
import PrivateIp from './anomaly/privateIP';
import ProfanityFilter from './anomaly/profanityFilter';
import RefererAnomaly from './anomaly/refererAnomaly';
import SequenceAnalysis from './anomaly/sequenceAnalysis';
import TimestampReplay from './anomaly/timestampReplay';
import TimingAnomaly from './anomaly/timingAnomaly';
import UnicodeNormalization from './anomaly/unicodeNormalization';
import AccountEnumeration from './auth/accountEnumeration';
import BasicAuthAnomaly from './auth/basicAuthAnomaly';
import BruteForce from './auth/bruteForce';
import CookieAbuse from './auth/cookieAbuse';
import CookieTampering from './auth/cookieTampering';
import CredentialStuffing from './auth/credentialStuffing';
import CredentialsInUrl from './auth/credentialsInUrl';
import CrossTenantViolation from './auth/crossTenantViolation';
import Csrf from './auth/csrf';
import ForcedBrowsing from './auth/forcedBrowsing';
import ImpossibleTravel from './auth/impossibleTravel';
import InvalidBearer from './auth/invalidBearer';
import JwtHeaderAbuse from './auth/jwtHeaderAbuse';
import JwtHeaderAttacks from './auth/jwtHeaderAttacks';
import JwtValidation from './auth/jwtValidation';
import MissingAuthentication from './auth/missingAuth';
import OauthFlowValidation from './auth/oauthFlowValidation';
import OtpBruteForce from './auth/otpBruteForce';
import PasswordSpraying from './auth/passwordSpraying';
import SessionBinding from './auth/sessionBinding';
import SessionFixation from './auth/sessionFixation';
import TokenReplay from './auth/tokenReplay';
import DatacenterAsn from './bot/datacenterAsn';
import GeoPolicy from './bot/geoPolicy';
import HeaderOrderFingerprint from './bot/headerOrderFingerprint';
import HeadlessBrowser from './bot/headlessBrowser';
import IpReputation from './bot/ipReputation';
import NotFoundSpike from './bot/notFoundSpike';
import ScannerSignature from './bot/scannerSignature';
import SensitiveFileProbe from './bot/sensitiveFileProbe';
import TlsFingerprint from './bot/tlsFingerprint';
import TorExitNode from './bot/torExitNode';
import UserAgentAnomaly from './bot/userAgentAnomaly';
import PiiInRequest from './dataLeakage/piiInRequest';
import ResponseLeak from './dataLeakage/responseLeak';
import ResponseSizeAnomaly from './dataLeakage/responseSizeAnomaly';
import SecretsInPayload from './dataLeakage/secretsInPayload';
import CodeInjection from './injection/codeInjection';
import CommandInjection from './injection/commandinjection';
import ControlCharacter from './injection/controlCharacter';
import CssInjection from './injection/cssInjection';
import CsvInjection from './injection/csvInjection';
import EmailHeaderInjection from './injection/emailHeaderInjection';
import ExpressionLanguageInjection from './injection/expressionLanguageInjection';
import GraphqlInjection from './injection/graphqlInjection';
import HttpParameterPollution from './injection/httpParameterPollution';
import InsecureDeserialization from './injection/insecureDeserialization';
import JndiLookup from './injection/jndiLookup';
import LdapInjection from './injection/ldapInjection';
import MaliciousFileUpload from './injection/maliciousFileUpload';
import NoSqlInjection from './injection/noSQLInjection';
import NullByte from './injection/nullByte';
import PathTraversal from './injection/pathTraversal';
import PolyglotFile from './injection/polyglotFile';
import PromptInjection from './injection/promptInjection';
import PrototypePollution from './injection/prototypePollution';
import RegexInjection from './injection/regexInjection';
import Shellshock from './injection/shellshock';
import SqlInjection from './injection/sqlinjection';
import SsiInjection from './injection/ssiInjection';
import Ssti from './injection/ssti';
import SvgScript from './injection/svgScript';
import WebshellSignature from './injection/webshellSignature';
import XpathInjection from './injection/xpathInjection';
import Xss from './injection/xss';
import Xxe from './injection/xxe';
import ZipSlip from './injection/zipSlip';
import AbsoluteUriRequest from './protocol/absoluteUriRequest';
import ChunkedEncodingAnomaly from './protocol/chunkedEncodingAnomaly';
import DuplicateHeaders from './protocol/duplicateHeaders';
import HopByHopAbuse from './protocol/hopByHopAbuse';
import HostHeaderInjection from './protocol/hostHeaderInjection';
import InvalidHeaderChars from './protocol/invalidHeaderChars';
import RequestSmuggling from './protocol/requestSmuggling';
import WebsocketOrigin from './protocol/websocketOrigin';
import XForwardedForSpoofing from './protocol/xForwardedForSpoofing';
import ArchiveExpansionRatio from './resource/archiveExpantionRatio';
import ArrayLength from './resource/arrayLength';
import CompressedBodyRatio from './resource/compressedBodyRatio';
import ConcurrentConnections from './resource/concurrentConnections';
import CookieSize from './resource/cookieSize';
import EndpointQuota from './resource/endpointQuota';
import ExpensiveQuery from './resource/expensiveQuery';
import FileSize from './resource/fileSize';
import GraphqlComplexity from './resource/graphqlComplexity';
import GraphqlIntrospection from './resource/graphqlIntrospection';
import HeaderCount from './resource/headerCount';
import ImageDimensions from './resource/imageDimensions';
import JsonDepth from './resource/jsonDepth';
import MultipartPartCount from './resource/multipartPartCount';
import ObjectKeyCount from './resource/objectKeyCount';
import PaginationAbuse from './resource/paginationAbuse';
import QueryParamCount from './resource/queryParamCount';
import RangeHeaderAbuse from './resource/rangeHeaderAbuse';
import RateLimit from './resource/rateLimit';
import RequestSize from './resource/requestSize';
import ScrapingPattern from './resource/scrapingPattern';
import SlowRequest from './resource/slowRequest';
import SmsEmailPumping from './resource/smsEmailPumping';
import WebsocketAbuse from './resource/websocketAbuse';
import XmlBomb from './resource/xmlBomb';
import AdditionalProperties from './schema/additionalProperties';
import ArrayUniqueness from './schema/arrayUniqueness';
import DuplicateJsonKeys from './schema/duplicateJsonKeys';
import EnumValidation from './schema/enumValidation';
import FileNameValidation from './schema/fileNameValidation';
import FormatValidation from './schema/formatValidation';
import IntegerRange from './schema/integerRange';
import InvalidUtf8 from './schema/invalidUtf8';
import JsonSchemaCheck from './schema/jsonSchema';
import MimeType from './schema/mimeType';
import NumberSpecialValues from './schema/numberSpecialValues';
import OpenApiConformance from './schema/openApiConformance';
import RegexPattern from './schema/regexPattern';
import RequiredFields from './schema/requiredFields';
import StringLength from './schema/stringLength';
import TypeCheck from './schema/typeCheck';
import TypeCoercion from './schema/typeCoercion';
import CachePoisoning from './url/cachePoisoning';
import CloudMetadata from './url/cloudMetadata';
import DnsRebinding from './url/dnsRebinding';
import IdnHomograph from './url/idnHomograph';
import IpObfuscation from './url/ipObfuscation';
import OpenRedirect from './url/openRedirect';
import PathNormalization from './url/pathNormalization';
import Ssrf from './url/ssrf';
import UrlLength from './url/urlLength';
import UrlParserDifferential from './url/urlParserDifferential';
import UrlValidator from './url/urlValidator';
import WebCacheDeception from './url/webCacheDeception';

type ToolFactories = { [Id in ToolId]: (config: ToolConfig<Id>, state: ToolState) => Tool<ToolContextType> };

// One implementation per contract in TOOL_CONTRACTS. The mapped type makes a contract without an
// implementation (or the reverse) a compile error.
const FACTORIES: ToolFactories = {
    absolute_uri_request: config => new AbsoluteUriRequest(config),
    account_enumeration: (config, state) => new AccountEnumeration(config, state),
    additional_properties: config => new AdditionalProperties(config),
    archive_expansion_ratio: config => new ArchiveExpansionRatio(config),
    array_length: config => new ArrayLength(config),
    array_uniqueness: config => new ArrayUniqueness(config),
    basic_auth_anomaly: config => new BasicAuthAnomaly(config),
    brute_force: (config, state) => new BruteForce(config, state),
    business_logic_tampering: config => new BusinessLogicTampering(config),
    cache_poisoning: config => new CachePoisoning(config),
    chunked_encoding_anomaly: config => new ChunkedEncodingAnomaly(config),
    cloud_metadata: () => new CloudMetadata(),
    code_injection: () => new CodeInjection(),
    command_injection: () => new CommandInjection(),
    compressed_body_ratio: config => new CompressedBodyRatio(config),
    concurrent_connections: (config, state) => new ConcurrentConnections(config, state),
    content_type_mismatch: () => new ContentTypeMismatch(),
    control_character: () => new ControlCharacter(),
    cookie_abuse: config => new CookieAbuse(config),
    cookie_size: config => new CookieSize(config),
    cookie_tampering: config => new CookieTampering(config),
    credential_stuffing: (config, state) => new CredentialStuffing(config, state),
    credentials_in_url: config => new CredentialsInUrl(config),
    cross_tenant_violation: config => new CrossTenantViolation(config),
    csrf: config => new Csrf(config),
    css_injection: () => new CssInjection(),
    csv_injection: () => new CsvInjection(),
    datacenter_asn: config => new DatacenterAsn(config),
    dns_rebinding: config => new DnsRebinding(config),
    double_encoding: () => new DoubleEncoding(),
    duplicate_headers: () => new DuplicateHeaders(),
    duplicate_json_keys: () => new DuplicateJsonKeys(),
    duplicate_request: (config, state) => new DuplicateRequest(config, state),
    email_header_injection: () => new EmailHeaderInjection(),
    encoded_payload: () => new EncodedPayload(),
    endpoint_quota: (config, state) => new EndpointQuota(config, state),
    entropy_analysis: config => new EntropyAnalysis(config),
    enum_validation: config => new EnumValidation(config),
    expensive_query: config => new ExpensiveQuery(config),
    expression_language_injection: () => new ExpressionLanguageInjection(),
    file_name_validation: config => new FileNameValidation(config),
    file_size: config => new FileSize(config),
    forced_browsing: config => new ForcedBrowsing(config),
    format_validation: config => new FormatValidation(config),
    geo_policy: config => new GeoPolicy(config),
    graphql_complexity: config => new GraphqlComplexity(config),
    graphql_injection: config => new GraphqlInjection(config),
    graphql_introspection: config => new GraphqlIntrospection(config),
    header_count: config => new HeaderCount(config),
    header_order_fingerprint: () => new HeaderOrderFingerprint(),
    headless_browser: config => new HeadlessBrowser(config),
    honeypot_endpoint: config => new HoneypotEndpoint(config),
    honeypot_field: config => new HoneypotField(config),
    hop_by_hop_abuse: () => new HopByHopAbuse(),
    host_header_injection: config => new HostHeaderInjection(config),
    http_parameter_pollution: () => new HttpParameterPollution(),
    idn_homograph: config => new IdnHomograph(config),
    image_dimensions: config => new ImageDimensions(config),
    impossible_travel: (config, state) => new ImpossibleTravel(config, state),
    insecure_deserialization: () => new InsecureDeserialization(),
    integer_range: config => new IntegerRange(config),
    invalid_bearer: config => new InvalidBearer(config),
    invalid_header_chars: () => new InvalidHeaderChars(),
    invalid_utf8: config => new InvalidUtf8(config),
    ip_obfuscation: () => new IpObfuscation(),
    ip_reputation: config => new IpReputation(config),
    jndi_lookup: () => new JndiLookup(),
    json_depth: config => new JsonDepth(config),
    json_schema: config => new JsonSchemaCheck(config),
    jwt_header_abuse: config => new JwtHeaderAbuse(config),
    jwt_header_attacks: config => new JwtHeaderAttacks(config),
    jwt_validation: config => new JwtValidation(config),
    ldap_injection: () => new LdapInjection(),
    malicious_file_upload: () => new MaliciousFileUpload(),
    mass_assignment: config => new MassAssignment(config),
    method_anomaly: config => new MethodAnomaly(config),
    method_override: () => new MethodOverride(),
    mime_type: config => new MimeType(config),
    missing_authentication: config => new MissingAuthentication(config),
    multipart_part_count: config => new MultipartPartCount(config),
    nosql_injection: () => new NoSqlInjection(),
    not_found_spike: (config, state) => new NotFoundSpike(config, state),
    null_byte: () => new NullByte(),
    number_special_values: config => new NumberSpecialValues(config),
    oauth_flow_validation: (config, state) => new OauthFlowValidation(config, state),
    object_key_count: config => new ObjectKeyCount(config),
    open_redirect: config => new OpenRedirect(config),
    openapi_conformance: config => new OpenApiConformance(config),
    otp_brute_force: (config, state) => new OtpBruteForce(config, state),
    overlong_utf8: () => new OverlongUtf8(),
    pagination_abuse: config => new PaginationAbuse(config),
    password_spraying: (config, state) => new PasswordSpraying(config, state),
    path_normalization: config => new PathNormalization(config),
    path_traversal: () => new PathTraversal(),
    pii_in_request: config => new PiiInRequest(config),
    polyglot_file: () => new PolyglotFile(),
    private_ip: () => new PrivateIp(),
    profanity_filter: config => new ProfanityFilter(config),
    prompt_injection: () => new PromptInjection(),
    prototype_pollution: () => new PrototypePollution(),
    query_param_count: config => new QueryParamCount(config),
    range_header_abuse: config => new RangeHeaderAbuse(config),
    rate_limit: (config, state) => new RateLimit(config, state),
    referer_anomaly: config => new RefererAnomaly(config),
    regex_injection: () => new RegexInjection(),
    regex_pattern: config => new RegexPattern(config),
    request_size: config => new RequestSize(config),
    request_smuggling: () => new RequestSmuggling(),
    required_fields: config => new RequiredFields(config),
    response_leak: () => new ResponseLeak(),
    response_size_anomaly: (config, state) => new ResponseSizeAnomaly(config, state),
    scanner_signature: () => new ScannerSignature(),
    scraping_pattern: (config, state) => new ScrapingPattern(config, state),
    secrets_in_payload: config => new SecretsInPayload(config),
    sensitive_file_probe: () => new SensitiveFileProbe(),
    sequence_analysis: (config, state) => new SequenceAnalysis(config, state),
    session_binding: (config, state) => new SessionBinding(config, state),
    session_fixation: config => new SessionFixation(config),
    shellshock: () => new Shellshock(),
    slow_request: config => new SlowRequest(config),
    sms_email_pumping: (config, state) => new SmsEmailPumping(config, state),
    sql_injection: () => new SqlInjection(),
    ssi_injection: () => new SsiInjection(),
    ssrf: () => new Ssrf(),
    ssti: () => new Ssti(),
    string_length: config => new StringLength(config),
    svg_script: () => new SvgScript(),
    timestamp_replay: (config, state) => new TimestampReplay(config, state),
    timing_anomaly: (config, state) => new TimingAnomaly(config, state),
    tls_fingerprint: config => new TlsFingerprint(config),
    token_replay: (config, state) => new TokenReplay(config, state),
    tor_exit_node: config => new TorExitNode(config),
    type_coercion: config => new TypeCoercion(config),
    unicode_normalization: () => new UnicodeNormalization(),
    url_length: config => new UrlLength(config),
    url_parser_differential: () => new UrlParserDifferential(),
    url_validator: config => new UrlValidator(config),
    user_agent_anomaly: config => new UserAgentAnomaly(config),
    web_cache_deception: config => new WebCacheDeception(config),
    webshell_signature: () => new WebshellSignature(),
    websocket_abuse: (config, state) => new WebsocketAbuse(config, state),
    websocket_origin: config => new WebsocketOrigin(config),
    x_forwarded_for_spoofing: config => new XForwardedForSpoofing(config),
    xml_bomb: config => new XmlBomb(config),
    xpath_injection: () => new XpathInjection(),
    xss: () => new Xss(),
    xxe: () => new Xxe(),
    zip_slip: () => new ZipSlip(),
    zod_type_check: config => new TypeCheck(config),
};

/**
 * Builds a tool from its id and its configuration as a policy sent it. The configuration is validated
 * against the tool's contract and its defaults applied; a ZodError is thrown when it breaks the contract.
 * Tools that look across requests keep their state in `state` (Redis); the others ignore it.
 */
export function createTool(id: ToolId, config: unknown, state: ToolState): Tool<ToolContextType> {
    const factory = FACTORIES[id] as (config: unknown, state: ToolState) => Tool<ToolContextType>;
    return factory(parseToolConfig(id, config), state);
}
