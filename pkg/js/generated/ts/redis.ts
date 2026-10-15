

/**
 * Connect tries to connect redis server with password
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * const connected = redis.Connect('acme.com', 6379, 'password');
 * ```
 */
export function Connect(host: string, port: number, password: string): boolean | null {
    return null;
}



/**
 * ConnectWithOptions tries to connect to Redis using the supplied options.
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * const opts = new redis.RedisOptions();
 * opts.Host = 'acme.com';
 * opts.Port = 6379;
 * opts.Password = 'password';
 * opts.DB = 1;
 * const connected = redis.ConnectWithOptions(opts);
 * ```
 */
export function ConnectWithOptions(opts: RedisOptions): boolean | null {
    return null;
}



/**
 * RedisOptions defines the connection options for a Redis server.
 */
export interface RedisOptions {
    
    Host?: string,
    
    Port?: number,
    
    Password?: string,
    
    DB?: number,
    
    Timeout?: number,
}



/**
 * GetServerInfo returns the server info for a redis server
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * const info = redis.GetServerInfo('acme.com', 6379);
 * ```
 */
export function GetServerInfo(host: string, port: number): string | null {
    return null;
}



/**
 * GetServerInfoAuth returns the server info for a redis server
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * const info = redis.GetServerInfoAuth('acme.com', 6379, 'password');
 * ```
 */
export function GetServerInfoAuth(host: string, port: number, password: string): string | null {
    return null;
}



/**
 * IsAuthenticated checks if the redis server requires authentication
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * const isAuthenticated = redis.IsAuthenticated('acme.com', 6379);
 * ```
 */
export function IsAuthenticated(host: string, port: number): boolean | null {
    return null;
}



/**
 * RunLuaScript runs a lua script on the redis server
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * // Old signature (backwards compatible) - keys and args are optional
 * const result = redis.RunLuaScript('acme.com', 6379, 'password', 'return redis.call("ping")');
 * // New signature with keys and args
 * const result = redis.RunLuaScript('acme.com', 6379, 'password', 'return redis.call("get", KEYS[1])', ['mykey'], []);
 * ```
 */
export function RunLuaScript(host: string, port: number, password: string, script: string, keys?: string[] | any, args?: string[] | any): any | null {
    return null;
}

