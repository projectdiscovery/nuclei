export interface AuthToken {}

export interface AuthFactory {
    password(username: string, password: string): AuthToken;
    ntHash(username: string, ntHash: string, ntHashPart?: string): AuthToken;
    kerberos(username: string, options?: Record<string, any>): AuthToken;
    aesKey(username: string, aesKey: string, options?: Record<string, any>): AuthToken;
    ccache(path: string): AuthToken;
    pfx(username: string, pfxPath: string, pfxPassword: string): AuthToken;
}

export const Auth: AuthFactory = {} as AuthFactory;

export interface CleanupResult {
    attempted: boolean;
    succeeded: boolean;
    artifacts?: string[];
}

export interface Result {
    ok: boolean;
    module: string;
    method: string;
    target: string;
    stdout: string;
    stderr: string;
    exit_code: number;
    output_collected: boolean;
    output_method?: string;
    duration_ms: number;
    error?: string;
    cleanup: CleanupResult;
}

export interface ExecutionOptions {
    timeout?: number;
    output?: boolean;
    output_method?: string;
    output_timeout?: number;
    no_delete_output?: boolean;
    directory?: string;
}

export class Client {
    constructor(target: string, auth: AuthToken) {}
    public setOptions(opts: ExecutionOptions): void { return; }
    public mmc(executable: string, args: string, opts?: ExecutionOptions): Result | null { return null; }
    public MMC(executable: string, args: string, opts?: ExecutionOptions): Result | null { return null; }
}
