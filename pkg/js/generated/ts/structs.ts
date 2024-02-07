

/**
 * StructsPack returns a byte slice containing the values of msg slice packed according to the given format.
 * The items of msg slice must match the values required by the format exactly.
 * Ex: structs.pack("H", 0)
 * @example
 * ```javascript
 * const structs = require('nuclei/structs');
 * const packed = structs.Pack('H', [0]);
 * ```
 */
export function Pack(formatStr: string, msg: any): Uint8Array | null {
    return null;
}



/**
 * StructsCalcSize returns the number of bytes needed to pack the values according to the given format.
 * Ex: structs.CalcSize("H")
 * @example
 * ```javascript
 * const structs = require('nuclei/structs');
 * const size = structs.CalcSize('H');
 * ```
 */
export function StructsCalcSize(format: string): number | null {
    return null;
}



/**
 * StructsUnpack the byte slice (presumably packed by Pack(format, msg)) according to the given format.
 * The result is a []interface{} slice even if it contains exactly one item.
 * The byte slice must contain not less the amount of data required by the format
 * (len(msg) must more or equal CalcSize(format)).
 * Ex: structs.Unpack(">I", buff[:nb])
 * @example
 * ```javascript
 * const structs = require('nuclei/structs');
 * const result = structs.Unpack('H', [0]);
 * ```
 */
export function Unpack(format: string, msg: Uint8Array): any | null {
    return null;
}

