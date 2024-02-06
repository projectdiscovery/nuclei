

/**
 * NewBuffer creates a new buffer from a byte slice.
 */
export function NewBuffer(call: any): any {
    return undefined;
}



/**
 * Buffer Class
 */
export class Buffer {
    

    // Constructor of Buffer
    constructor() {}
    /**
    * Write appends a byte slice to the buffer.
    */
    public Write(data: Uint8Array): Buffer {
        return this;
    }
    

    /**
    * WriteString appends a string to the buffer.
    */
    public WriteString(data: string): Buffer {
        return this;
    }
    

    /**
    * Bytes returns the byte slice of the buffer.
    */
    public Bytes(): Uint8Array {
        return new Uint8Array(8);
    }
    

    /**
    * String returns the string representation of the buffer.
    */
    public String(): string {
        return "";
    }
    

    /**
    * Len returns the length of the buffer.
    */
    public Len(): number {
        return 0;
    }
    

    /**
    * Hex returns the hex representation of the buffer.
    */
    public Hex(): string {
        return "";
    }
    

    /**
    * Hexdump returns the hexdump representation of the buffer.
    */
    public Hexdump(): string {
        return "";
    }
    

    /**
    * Pack uses structs.Pack and packs given data and appends it to the buffer.
    * it packs the data according to the given format.
    * @throws {Error} - if the operation fails
    */
    public Pack(formatStr: string, msg: any): void {
        return;
    }
    

}

