


export const IKE_EXCHANGE_AUTH = 35;


export const IKE_EXCHANGE_CREATE_CHILD_SA = 36;


export const IKE_EXCHANGE_INFORMATIONAL = 37;


export const IKE_EXCHANGE_SA_INIT = 34;


export const IKE_FLAGS_InitiatorBitCheck = 0x08;


export const IKE_NOTIFY_NO_PROPOSAL_CHOSEN = 14;


export const IKE_NOTIFY_USE_TRANSPORT_MODE = 16391;


export const IKE_VERSION_2 = 0x20;

/**
 * IKEMessage is the IKEv2 message
 * IKEv2 implements a limited subset of IKEv2 Protocol, specifically
 * the IKE_NOTIFY and IKE_NONCE payloads and the IKE_SA_INIT exchange.
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
    * @example
    * ```javascript
    * const ikev2 = require('nuclei/ikev2');
    * const message = new ikev2.IKEMessage();
    * const nonce = new ikev2.IKENonce();
    * nonce.NonceData = [1, 2, 3];
    * message.AppendPayload(nonce);
    * ```
    */
    public AppendPayload(payload: any): void {
        return;
    }
    

    /**
    * Encode encodes the final IKE message
    * @example
    * ```javascript
    * const ikev2 = require('nuclei/ikev2');
    * const message = new ikev2.IKEMessage();
    * const nonce = new ikev2.IKENonce();
    * nonce.NonceData = [1, 2, 3];
    * message.AppendPayload(nonce);
    * log(message.Encode());
    * ```
    */
    public Encode(): Uint8Array | null {
        return null;
    }
    

}



/**
 * IKENonce is the IKEv2 Nonce payload
 * this implements the IKEPayload interface
 * @example
 * ```javascript
 * const ikev2 = require('nuclei/ikev2');
 * const nonce = new ikev2.IKENonce();
 * nonce.NonceData = [1, 2, 3];
 * ```
 */
export interface IKENonce {
    
    NonceData?: Uint8Array,
}



/**
 * IKEv2Notify is the IKEv2 Notification payload
 * this implements the IKEPayload interface
 * @example
 * ```javascript
 * const ikev2 = require('nuclei/ikev2');
 * const notify = new ikev2.IKENotification();
 * notify.NotifyMessageType = ikev2.IKE_NOTIFY_NO_PROPOSAL_CHOSEN;
 * notify.NotificationData = [1, 2, 3];
 * ```
 */
export interface IKENotification {
    
    NotifyMessageType?: number,
    
    NotificationData?: Uint8Array,
}

