

/**
 * Buffer is a bytes/Uint8Array type in javascript
 * @example
 * ```javascript
 * const bytes = require('nuclei/bytes');
 * const bytes = new bytes.Buffer();
 * ```
 * @example
 * ```javascript
 * const bytes = require('nuclei/bytes');
 * // optionally it can accept existing byte/Uint8Array as input
 * const bytes = new bytes.Buffer([1, 2, 3]);
 * ```
 */
export class Buffer {
    

    // Constructor of Buffer
    constructor() {}
    /**
    * Write appends the given data to the buffer.
    * @example
    * ```javascript
    * const bytes = require('nuclei/bytes');
    * const buffer = new bytes.Buffer();
    * buffer.Write([1, 2, 3]);
    * ```
    */
    public Write(data: Uint8Array): Buffer {
        return this;
    }
    

    /**
    * WriteString appends the given string data to the buffer.
    * @example
    * ```javascript
    * const bytes = require('nuclei/bytes');
    * const buffer = new bytes.Buffer();
    * buffer.WriteString('hello');
    * ```
    */
    public WriteString(data: string): Buffer {
        return this;
    }
    

    /**
    * Bytes returns the byte representation of the buffer.
    * @example
    * ```javascript
    * const bytes = require('nuclei/bytes');
    * const buffer = new bytes.Buffer();
    * buffer.WriteString('hello');
    * log(buffer.Bytes());
    * ```
    */
    public Bytes(): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * String returns the string representation of the buffer.
    * @example
    * ```javascript
    * const bytes = require('nuclei/bytes');
    * const buffer = new bytes.Buffer();
    * buffer.WriteString('hello');
    * log(buffer.String());
    * ```
    */
    public String(): string {
        return "";
    }
    

    /**
    * Len returns the length of the buffer.
    * @example
    * ```javascript
    * const bytes = require('nuclei/bytes');
    * const buffer = new bytes.Buffer();
    * buffer.WriteString('hello');
    * log(buffer.Len());
    * ```
    */
    public Len(): number {
        return 0;
    }
    

    /**
    * Hex returns the hex representation of the buffer.
    * @example
    * ```javascript
    * const bytes = require('nuclei/bytes');
    * const buffer = new bytes.Buffer();
    * buffer.WriteString('hello');
    * log(buffer.Hex());
    * ```
    */
    public Hex(): string {
        return "";
    }
    

    /**
    * Hexdump returns the hexdump representation of the buffer.
    * @example
    * ```javascript
    * const bytes = require('nuclei/bytes');
    * const buffer = new bytes.Buffer();
    * buffer.WriteString('hello');
    * log(buffer.Hexdump());
    * ```
    */
    public Hexdump(): string {
        return "";
    }
    

    /**
    * Pack uses structs.Pack and packs given data and appends it to the buffer.
    * it packs the data according to the given format.
    * @example
    * ```javascript
    * const bytes = require('nuclei/bytes');
    * const buffer = new bytes.Buffer();
    * buffer.Pack('I', 123);
    * ```
    */
    public Pack(formatStr: string, msg: any): void {
        return;
    }
    

}

