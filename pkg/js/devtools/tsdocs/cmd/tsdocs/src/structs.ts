
/**
 * StructsUnpack the byte slice (presumably packed by Pack(format, msg)) according to the given format.
 * The result is a []interface{} slice even if it contains exactly one item.
 * The byte slice must contain not less the amount of data required by the format
 * (len(msg) must more or equal CalcSize(format)).
 * Ex: structs.Unpack(">I", buff[:nb])
* @throws {Error} - if the operation fails
 */
export function Unpack(format: string, msg: Uint8Array): [] | null {
    return null;
}


/**
 * StructsPack returns a byte slice containing the values of msg slice packed according to the given format.
 * The items of msg slice must match the values required by the format exactly.
 * Ex: structs.pack("H", 0)
* @throws {Error} - if the operation fails
 */
export function Pack(formatStr: string, msg: ): Uint8Array | null {
    return null;
}


/**
 * StructsCalcSize returns the number of bytes needed to pack the values according to the given format.
* @throws {Error} - if the operation fails
 */
export function StructsCalcSize(format: string): number | null {
    return null;
}

