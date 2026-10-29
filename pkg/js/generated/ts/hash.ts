

/**
 * New returns a running hash for algorithm: md5, sha1, sha256, sha512 or
 * mmh3. Sum gives the same value as the DSL function of the same name over
 * all the data written.
 * @example
 * ```javascript
 * const hash = require('nuclei/hash');
 * const h = hash.New('sha256');
 * ```
 */
export function New(algorithm: string): Hash | null {
    return null;
}



/**
 * Hash is a running hash. Its memory does not grow with the data written.
 * @example
 * ```javascript
 * const hash = require('nuclei/hash');
 * const h = hash.New('sha256');
 * h.WriteString('hello');
 * log(h.Sum());
 * ```
 */
export class Hash {
    

    // Constructor of Hash
    constructor() {}
    /**
    * Write adds data to the hash.
    * @example
    * ```javascript
    * const hash = require('nuclei/hash');
    * const h = hash.New('sha256');
    * h.Write([104, 105]);
    * ```
    */
    public Write(data: Uint8Array): void {
        return;
    }
    

    /**
    * WriteString adds the string data to the hash.
    * @example
    * ```javascript
    * const hash = require('nuclei/hash');
    * const h = hash.New('sha256');
    * h.WriteString('hi');
    * ```
    */
    public WriteString(data: string): void {
        return;
    }
    

    /**
    * Sum returns the hash of the data written so far: lowercase hex, or for
    * mmh3 a signed decimal integer. Writing more afterwards continues the hash.
    * @example
    * ```javascript
    * const hash = require('nuclei/hash');
    * const h = hash.New('mmh3');
    * h.WriteString('hello');
    * log(h.Sum());
    * ```
    */
    public Sum(): string | null {
        return null;
    }
    

}

