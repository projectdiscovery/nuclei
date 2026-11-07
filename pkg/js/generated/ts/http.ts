
/**
 * Client is an HTTP client for nuclei JS templates.
 * @example
 * ```javascript
 * const http = require('nuclei/http');
 * const client = new http.Client();
 * const resp = client.Get('https://example.com');
 * log(resp.StatusCode + ' ' + resp.Body);
 * ```
 */
export class Client {
    

    public TimeoutSeconds?: number;
    

    public FollowRedirects?: boolean;
    

    public MaxRedirects?: number;
    

    public MaxBodyBytes?: number;
    

    public DisableCookie?: boolean;
    

    // Constructor of Client
    constructor(options?: Options) {}
    /**
    * SetHeader sets a default request header on the client.
    * @example
    * ```javascript
    * const http = require('nuclei/http');
    * const client = new http.Client();
    * client.SetHeader('User-Agent', 'nuclei');
    * ```
    */
    public SetHeader(key: string, value: string): void {
        return;
    }
    

    /**
    * Get performs an HTTP GET.
    * @example
    * ```javascript
    * const http = require('nuclei/http');
    * const client = new http.Client();
    * const resp = client.Get('https://example.com');
    * ```
    */
    public Get(rawURL: string): Response | null {
        return null;
    }
    

    /**
    * Head performs an HTTP HEAD.
    * @example
    * ```javascript
    * const http = require('nuclei/http');
    * const client = new http.Client();
    * const resp = client.Head('https://example.com');
    * ```
    */
    public Head(rawURL: string): Response | null {
        return null;
    }
    

    /**
    * Post performs an HTTP POST with the given body string.
    * @example
    * ```javascript
    * const http = require('nuclei/http');
    * const client = new http.Client();
    * const resp = client.Post('https://example.com/login', 'user=a&pass=b');
    * ```
    */
    public Post(rawURL: string, body: string): Response | null {
        return null;
    }
    

    /**
    * Request performs an HTTP request with the given method and optional body.
    * @example
    * ```javascript
    * const http = require('nuclei/http');
    * const client = new http.Client();
    * const resp = client.Request('PUT', 'https://example.com/item', '{"a":1}');
    * ```
    */
    public Request(method: string, rawURL: string, body: string): Response | null {
        return null;
    }
}


/**
 * DecodeNTLM decodes an NTLM SSP blob from a WWW-Authenticate / Authorization
 * header value or raw base64. Accepts prefixes "NTLM " and "Negotiate ".
 * Only Type-2 (challenge) messages populate TargetInfo fields.
 * @example
 * ```javascript
 * const http = require('nuclei/http');
 * const info = http.DecodeNTLM('NTLM TlRMTVNTUAACAAAA...');
 * ```
 */
export function DecodeNTLM(blob: string): NTLMInfo | null {
    return null;
}


/**
 * Get is a package-level GET using a default client (redirects + cookies on).
 * @example
 * ```javascript
 * const http = require('nuclei/http');
 * const resp = http.Get('https://example.com');
 * ```
 */
export function Get(rawURL: string): Response | null {
    return null;
}


/**
 * Head is a package-level HEAD using a default client.
 * @example
 * ```javascript
 * const http = require('nuclei/http');
 * const resp = http.Head('https://example.com');
 * ```
 */
export function Head(rawURL: string): Response | null {
    return null;
}


/**
 * NegotiateNTLM returns a base64 Type-1 NTLM negotiate message suitable for
 * an Authorization header (without the "NTLM " prefix).
 * @example
 * ```javascript
 * const http = require('nuclei/http');
 * const client = new http.Client();
 * client.SetHeader('Authorization', 'NTLM ' + http.NegotiateNTLM());
 * const resp = client.Get('https://exchange.acme.local/ews/');
 * ```
 */
export function NegotiateNTLM(): string | null {
    return null;
}


/**
 * Post is a package-level POST using a default client.
 * @example
 * ```javascript
 * const http = require('nuclei/http');
 * const resp = http.Post('https://example.com/login', 'user=a&pass=b');
 * ```
 */
export function Post(rawURL: string, body: string): Response | null {
    return null;
}


/**
 * Request is a package-level request using a default client.
 * @example
 * ```javascript
 * const http = require('nuclei/http');
 * const resp = http.Request('OPTIONS', 'https://example.com', '');
 * ```
 */
export function Request(method: string, rawURL: string, body: string): Response | null {
    return null;
}


/**
 * NTLMInfo holds fields decoded from an NTLM Type-2 challenge
 * (Burp ntlm-challenge-decoder / nmap-style AV pairs).
 * @example
 * ```javascript
 * const http = require('nuclei/http');
 * const resp = http.Get('https://exchange.acme.local/ews/');
 * const info = http.DecodeNTLM(resp.GetHeader('WWW-Authenticate'));
 * log(info.DNSComputerName + ' ' + info.DNSDomainName);
 * ```
 */
export class NTLMInfo {
    

    public MessageType?: number;
    

    public TargetName?: string;
    

    public NetBIOSDomainName?: string;
    

    public NetBIOSComputerName?: string;
    

    public DNSDomainName?: string;
    

    public DNSComputerName?: string;
    

    public DNSTreeName?: string;
    

    public ProductVersion?: string;
    

    public Timestamp?: number;
    

    public UnixTimestamp?: number;
    

    // Constructor of NTLMInfo
    constructor() {}
}


/**
 * Options configures a Client. All fields are optional.
 * @example
 * ```javascript
 * const http = require('nuclei/http');
 * const opts = new http.Options();
 * opts.TimeoutSeconds = 15;
 * opts.MaxRedirects = 5;
 * const client = new http.Client(opts);
 * ```
 */
export class Options {
    

    public TimeoutSeconds?: number;
    

    public MaxRedirects?: number;
    

    public MaxBodyBytes?: number;
    

    public DisableRedirects?: boolean;
    

    public DisableCookie?: boolean;
    

    // Constructor of Options
    constructor() {}
}


/**
 * Response is an HTTP response returned by Client methods.
 * @example
 * ```javascript
 * const http = require('nuclei/http');
 * const resp = http.Get('https://example.com');
 * log(resp.StatusCode);
 * log(resp.GetHeader('Content-Type'));
 * ```
 */
export class Response {
    

    public StatusCode?: number;
    

    public URL?: string;
    

    public Body?: string;
    

    public Headers?: Record<string, string>;
    

    // Constructor of Response
    constructor() {}
    /**
    * GetHeader returns the first value for a header (case-insensitive), or "".
    * @example
    * ```javascript
    * const http = require('nuclei/http');
    * const resp = http.Get('https://example.com');
    * const ct = resp.GetHeader('content-type');
    * ```
    */
    public GetHeader(name: string): string | null {
        return null;
    }
}
