
/**
 * IKEMessage Class
 */
export class IKEMessage {
    

    /**
    */
    public InitiatorSPI: uint64;
    

    /**
    */
    public Version: number;
    

    /**
    */
    public ExchangeType: number;
    

    /**
    */
    public Flags: number;
    

    /**
    */
    public Payloads: IKEPayload[];
    

    /**
    * AppendPayload appends a payload to the IKE message
    */
    public AppendPayload(payload: IKEPayload): void {
        return;
    }
    

    /**
    * Encode encodes the final IKE message
    * @throws {Error} - if the operation fails
    */
    public Encode(): Uint8Array | null {
        return null;
    }
    

}


/**
 * IKENotification interface
 */
export interface IKENotification {
    
    NotifyMessageType?: number,
    
    NotificationData?: Uint8Array,
}


/**
 * IKENonce interface
 */
export interface IKENonce {
    
    NonceData?: Uint8Array,
}

