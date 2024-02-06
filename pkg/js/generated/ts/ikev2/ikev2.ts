


export const IKE_EXCHANGE_AUTH = 35;


export const IKE_EXCHANGE_CREATE_CHILD_SA = 36;


export const IKE_EXCHANGE_INFORMATIONAL = 37;


export const IKE_EXCHANGE_SA_INIT = 34;


export const IKE_FLAGS_InitiatorBitCheck = 0x08;


export const IKE_NOTIFY_NO_PROPOSAL_CHOSEN = 14;


export const IKE_NOTIFY_USE_TRANSPORT_MODE = 16391;


export const IKE_VERSION_2 = 0x20;

/**
 * IKEMessage Class
 */
export class IKEMessage {
    

    
    public InitiatorSPI?: number;
    

    
    public Version?: number;
    

    
    public ExchangeType?: number;
    

    
    public Flags?: number;
    

    // Constructor of IKEMessage
    constructor() {}
    /**
    * AppendPayload appends a payload to the IKE message
    * payload can be any of the payloads like IKENotification, IKENonce, etc.
    * @throws {Error} - if the operation fails
    */
    public AppendPayload(payload: any): void {
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
 * IKENonce interface
 */
export interface IKENonce {
    
    NonceData?: Uint8Array,
}



/**
 * IKENotification interface
 */
export interface IKENotification {
    
    NotifyMessageType?: number,
    
    NotificationData?: Uint8Array,
}

