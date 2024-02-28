

/**
 * IsOracle checks if a host is running an Oracle server
 * @example
 * ```javascript
 * const oracle = require('nuclei/oracle');
 * const isOracle = oracle.IsOracle('acme.com', 1521);
 * log(toJSON(isOracle));
 * ```
 */
export function IsOracle(host: string, port: number): IsOracleResponse | null {
    return null;
}



/**
 * IsOracleResponse is the response from the IsOracle function.
 * this is returned by IsOracle function.
 * @example
 * ```javascript
 * const oracle = require('nuclei/oracle');
 * const isOracle = oracle.IsOracle('acme.com', 1521);
 * ```
 */
export interface IsOracleResponse {
    
    IsOracle?: boolean,
    
    Banner?: string,
}

