

/**
 * NewDecoder returns a decoder for gzip, deflate, br, zstd, chunked or
 * identity. List several comma-separated, in the order they were applied.
 * @example
 * ```javascript
 * const compress = require('nuclei/compress');
 * const d = compress.NewDecoder('br');
 * // Content-Encoding: gzip sent with Transfer-Encoding: chunked
 * const c = compress.NewDecoder('gzip, chunked');
 * ```
 */
export function NewDecoder(encoding: string): Decoder | null {
    return null;
}



/**
 * Decoder decodes a compressed stream written to it in chunks. Each call
 * returns up to about 1 MB; call Read until it returns nothing before the
 * next Write.
 * @example
 * ```javascript
 * const compress = require('nuclei/compress');
 * const hash = require('nuclei/hash');
 * const d = compress.NewDecoder('gzip');
 * const h = hash.New('sha256');
 * for (const chunk of chunks) {
 *   for (let out = d.Write(chunk); out.length > 0; out = d.Read()) h.Write(out);
 * }
 * for (let out = d.Close(); out.length > 0; out = d.Read()) h.Write(out);
 * log(h.Sum());
 * ```
 */
export class Decoder {
    

    // Constructor of Decoder
    constructor() {}
    /**
    * Write decodes the next chunk and returns up to about 1 MB of output.
    * @example
    * ```javascript
    * const compress = require('nuclei/compress');
    * const d = compress.NewDecoder('gzip');
    * const out = d.Write(chunk);
    * ```
    */
    public Write(chunk: Uint8Array): Uint8Array | null {
        return null;
    }
    

    /**
    * Read returns more decoded bytes, or none once the decoder needs input.
    * @example
    * ```javascript
    * const compress = require('nuclei/compress');
    * const d = compress.NewDecoder('gzip');
    * for (let out = d.Write(chunk); out.length > 0; out = d.Read()) log(out.length);
    * ```
    */
    public Read(): Uint8Array | null {
        return null;
    }
    

    /**
    * Close ends the input and returns the last decoded bytes. A truncated
    * stream errors once the bytes before the cut have been returned.
    * @example
    * ```javascript
    * const compress = require('nuclei/compress');
    * const d = compress.NewDecoder('gzip');
    * d.Write(chunk);
    * for (let out = d.Close(); out.length > 0; out = d.Read()) log(out.length);
    * ```
    */
    public Close(): Uint8Array | null {
        return null;
    }
    

    /**
    * Finished reports whether a stream that marks its own end, such as a
    * chunked body, has ended and all its output was read.
    * @example
    * ```javascript
    * const compress = require('nuclei/compress');
    * const d = compress.NewDecoder('gzip, chunked');
    * while (!d.Finished()) for (let out = d.Write(conn.Recv(65536)); out.length > 0; out = d.Read()) log(out.length);
    * ```
    */
    public Finished(): boolean {
        return false;
    }
    

}

