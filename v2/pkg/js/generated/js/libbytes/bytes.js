/**@module bytes */

/**
 * @class
 * @classdesc Buffer is a minimal buffer implementation to store and retrieve data
 */
class Buffer {
    /**
    * @method
    * @description Bytes returns the byte slice of the buffer.
    * @returns {Uint8Array} - The byte slice of the buffer.
    * @example
    * let m = require('nuclei/bytes');
    * let b = m.Buffer();
    * let bytes = b.Bytes();
    */
    Bytes() {
        // implemented in go
    };

    /**
    * @method
    * @description Hex returns the hex representation of the buffer.
    * @returns {string} - The hex representation of the buffer.
    * @example
    * let m = require('nuclei/bytes');
    * let b = m.Buffer();
    * let hex = b.Hex();
    */
    Hex() {
        // implemented in go
    };

    /**
    * @method
    * @description Hexdump returns the hexdump representation of the buffer.
    * @returns {string} - The hexdump representation of the buffer.
    * @example
    * let m = require('nuclei/bytes');
    * let b = m.Buffer();
    * let hexdump = b.Hexdump();
    */
    Hexdump() {
        // implemented in go
    };

    /**
    * @method
    * @description Len returns the length of the buffer.
    * @returns {number} - The length of the buffer.
    * @example
    * let m = require('nuclei/bytes');
    * let b = m.Buffer();
    * let length = b.Len();
    */
    Len() {
        // implemented in go
    };

    /**
    * @method
    * @description Pack uses structs.Pack and packs given data and appends it to the buffer. It packs the data according to the given format.
    * @param {string} formatStr - The format string to pack the data.
    * @param {string} msg - The message to pack.
    * @returns {Buffer} - The buffer after packing the data.
    * @throws {error} - The error encountered during packing.
    * @example
    * let m = require('nuclei/bytes');
    * let b = m.Buffer();
    * b.Pack('format', 'message');
    */
    Pack(formatStr, msg) {
        // implemented in go
    };

    /**
    * @method
    * @description String returns the string representation of the buffer.
    * @returns {string} - The string representation of the buffer.
    * @example
    * let m = require('nuclei/bytes');
    * let b = m.Buffer();
    * let str = b.String();
    */
    String() {
        // implemented in go
    };

    /**
    * @method
    * @description Write appends a byte slice to the buffer.
    * @param {Uint8Array} data - The byte slice to append to the buffer.
    * @returns {Buffer} - The buffer after appending the byte slice.
    * @example
    * let m = require('nuclei/bytes');
    * let b = m.Buffer();
    * b.Write(new Uint8Array([1, 2, 3]));
    */
    Write(data) {
        // implemented in go
    };

    /**
    * @method
    * @description WriteString appends a string to the buffer.
    * @param {string} data - The string to append to the buffer.
    * @returns {Buffer} - The buffer after appending the string.
    * @example
    * let m = require('nuclei/bytes');
    * let b = m.Buffer();
    * b.WriteString('data');
    */
    WriteString(data) {
        // implemented in go
    };
};

/**
 * @function
 * @description NewBuffer creates a new buffer from a byte slice.
 * @param {Uint8Array} call - The byte slice to create the buffer from.
 * @returns {Buffer} - The new buffer created from the byte slice.
 * @example
 * let m = require('nuclei/bytes'); 
 * let buffer = m.NewBuffer(new Uint8Array([1, 2, 3]));
 */
function NewBuffer(call) {
    // implemented in go
};

module.exports = {
    Buffer: Buffer,
    NewBuffer: NewBuffer,
};