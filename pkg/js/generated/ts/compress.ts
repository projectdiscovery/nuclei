

/**
 * NewDecoder returns a decoder for the codings the HTTP engine decodes:
 * gzip, deflate (zlib), br and zstd, plus chunked for a Transfer-Encoding.
 * encoding may list several, comma-separated in the order they were applied,
 * the way HTTP headers list them; they are decoded last to first. identity
 * and an empty encoding pass the bytes through unchanged.
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
 * returns the bytes decoded so far, up to about 1 MB; call Read until it
 * returns no bytes before writing the next chunk. Memory stays bounded by
 * the format's window, at most 16 MB for brotli.
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
    * Write decodes the next compressed chunk and returns the bytes decoded so
    * far, up to about 1 MB.
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
    * Read returns more decoded bytes, up to about 1 MB. It returns no bytes once
    * the decoder needs the next chunk or the stream has ended.
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
    * Close ends the input and returns the last decoded bytes, up to about 1 MB;
    * call Read for the rest. A stream that was cut short raises an error once
    * all the bytes decoded before the cut have been returned.
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
    * Finished reports whether the stream has ended and every decoded byte has
    * been handed back. Only a format that marks its own end can finish before
    * Close: a chunked body finishes at its last chunk, so a template reading one
    * knows when to stop calling Recv.
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

