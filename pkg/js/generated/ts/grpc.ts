

/**
 * Client is a gRPC client for nuclei JS templates backed by grpcurl.
 * @example
 * ```javascript
 * const grpc = require('nuclei/grpc');
 * const client = new grpc.Client('grpc.acme.com:443');
 * const resp = client.Invoke('grpc.health.v1.Health/Check', '{}');
 * ```
 */
export class Client {
    

    public Target?: string;
    

    // Constructor of Client
    constructor(target: string, options?: Options) {}
    /**
    * Connect eagerly establishes the connection and descriptor source. It is
    * optional; other methods connect on demand.
    * @example
    * ```javascript
    * const grpc = require('nuclei/grpc');
    * const client = new grpc.Client('grpc.acme.com:443');
    * client.Connect();
    * ```
    */
    public Connect(): boolean | null {
        return null;
    }
    

    /**
    * ListServices returns the fully-qualified names of all services exposed by the
    * target (via reflection) or defined in the configured protoset.
    * @example
    * ```javascript
    * const grpc = require('nuclei/grpc');
    * const client = new grpc.Client('grpc.acme.com:443');
    * const services = client.ListServices();
    * ```
    */
    public ListServices(): string[] | null {
        return null;
    }
    

    /**
    * ListMethods returns the fully-qualified method names of the given service.
    * @example
    * ```javascript
    * const grpc = require('nuclei/grpc');
    * const client = new grpc.Client('grpc.acme.com:443');
    * const methods = client.ListMethods('grpc.health.v1.Health');
    * ```
    */
    public ListMethods(service: string): string[] | null {
        return null;
    }
    

    /**
    * DescribeSymbol returns the textual descriptor of a fully-qualified symbol
    * (service, method or message type).
    * @example
    * ```javascript
    * const grpc = require('nuclei/grpc');
    * const client = new grpc.Client('grpc.acme.com:443');
    * const text = client.DescribeSymbol('grpc.health.v1.Health');
    * ```
    */
    public DescribeSymbol(symbol: string): string | null {
        return null;
    }
    

    /**
    * Invoke calls a unary gRPC method with a JSON request and returns the JSON
    * response. The method must be in 'package.Service/Method' or
    * 'package.Service.Method' form. An empty message is treated as '{}'.
    * @example
    * ```javascript
    * const grpc = require('nuclei/grpc');
    * const client = new grpc.Client('grpc.acme.com:443');
    * const resp = client.Invoke('grpc.health.v1.Health/Check', '{"service":""}');
    * ```
    */
    public Invoke(method: string, message: string): string | null {
        return null;
    }
    

    /**
    * InvokeWithHeaders behaves like Invoke but also sends the given request
    * metadata. Each header must be in 'key: value' form.
    * @example
    * ```javascript
    * const grpc = require('nuclei/grpc');
    * const client = new grpc.Client('grpc.acme.com:443');
    * const resp = client.InvokeWithHeaders('acme.v1.Svc/Get', '{}', ['authorization: Bearer x']);
    * ```
    */
    public InvokeWithHeaders(method: string, message: string, headers: string[]): string | null {
        return null;
    }
    

    /**
    * Close releases the connection and any descriptor source resources.
    * @example
    * ```javascript
    * const grpc = require('nuclei/grpc');
    * const client = new grpc.Client('grpc.acme.com:443');
    * client.Close();
    * ```
    */
    public Close(): boolean | null {
        return null;
    }
    

}



/**
 * Options configures a gRPC Client. All fields are optional; the zero value
 * connects over TLS using the target host as the server name and resolves
 * the schema via server reflection.
 * @example
 * ```javascript
 * const grpc = require('nuclei/grpc');
 * const opts = new grpc.Options();
 * opts.Plaintext = true;
 * opts.TimeoutSeconds = 10;
 * const client = new grpc.Client('grpc.acme.com:443', opts);
 * ```
 */
export interface Options {
    
    Plaintext?: boolean,
    
    InsecureSkipVerify?: boolean,
    
    ServerName?: string,
    
    TimeoutSeconds?: number,
    
    ProtosetFile?: string,
    
    MaxRecvMsgSize?: number,
}
