/**
 * @module bytes
 */

/**
 * @class Buffer
 * @description Buffer is a minimal buffer implementation over a byte slice
 * that is used to pack/unpack binary data in nuclei js integration.
 */
class Buffer {
    /**
     * @method Bytes
     * @return {Array} byte slice of the buffer.
     */
    Bytes() {
        // implemented in go
    };

    /**
     * @method Hex
     * @return {string} hex representation of the buffer.
     */
    Hex() {
        // implemented in go
    };

    /**
     * @method Hexdump
     * @return {string} hexdump representation of the buffer.
     */
    Hexdump() {
        // implemented in go
    };

    /**
     * @method Len
     * @return {number} length of the buffer.
     */
    Len() {
        // implemented in go
    };

    /**
     * @method Pack
     * @param {string} formatStr - format string for packing data
     * @param {string} msg - message to be packed
     * @throws {Error} if packing fails
     */
    Pack(formatStr, msg) {
        // implemented in go
    };

    /**
     * @method String
     * @return {string} string representation of the buffer.
     */
    String() {
        // implemented in go
    };

    /**
     * @method Write
     * @param {Array} data - data to be appended to the buffer
     * @return {Buffer} updated buffer
     */
    Write(data) {
        // implemented in go
    };

    /**
     * @method WriteString
     * @param {string} data - string to be appended to the buffer
     * @return {Buffer} updated buffer
     */
    WriteString(data) {
        // implemented in go
    };
};

/**
 * @function NewBuffer
 * @param {any} call - parameter for creating new buffer
 */
function NewBuffer(call) {
    // implemented in go
};

module.exports = {
    Buffer: Buffer,
    NewBuffer: NewBuffer,
};