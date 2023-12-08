
/**
 * ListDir lists all files and directories within a path
 * depending on the itemType provided
 * itemType can be any one of ['file','dir','all']
* @throws {Error} - if the operation fails
 */
export function ListDir(path: string, itemType: string): string[] | null {
    return null;
}


/**
 * ReadFile reads file contents within permitted paths
* @throws {Error} - if the operation fails
 */
export function ReadFile(path: string): Uint8Array | null {
    return null;
}


/**
 * ReadFileAsString reads file contents within permitted paths
 * and returns content as string
* @throws {Error} - if the operation fails
 */
export function ReadFileAsString(path: string): string | null {
    return null;
}


/**
 * ReadFilesFromDir reads all files from a directory
 * and returns a array with file contents of all files
* @throws {Error} - if the operation fails
 */
export function ReadFilesFromDir(dir: string): string[] | null {
    return null;
}

