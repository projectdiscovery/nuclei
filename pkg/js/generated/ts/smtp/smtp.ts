

/**
 * SMTPClient Class
 */
export class SMTPClient {
    

    // Constructor of SMTPClient
    constructor() {}
    /**
    * IsSMTP checks if a host is running a SMTP server.
    * @throws {Error} - if the operation fails
    */
    public IsSMTP(host: string, port: number): IsSMTPResponse | null {
        return null;
    }
    

    /**
    * IsOpenRelay Method
    * @throws {Error} - if the operation fails
    */
    public IsOpenRelay(host: string, port: number, msg: SMTPMessage): boolean | null {
        return null;
    }
    

    /**
    * SendMail sends an email using the SMTP protocol.
    * @throws {Error} - if the operation fails
    */
    public SendMail(host: string, port: string, msg: SMTPMessage): boolean | null {
        return null;
    }
    

}



/**
 * SMTPMessage Class
 */
export class SMTPMessage {
    

    // Constructor of SMTPMessage
    constructor() {}
    /**
    * From adds the from field to the message
    */
    public From(email: string): SMTPMessage {
        return this;
    }
    

    /**
    * To adds the to field to the message
    */
    public To(email: string): SMTPMessage {
        return this;
    }
    

    /**
    * Subject adds the subject field to the message
    */
    public Subject(sub: string): SMTPMessage {
        return this;
    }
    

    /**
    * Body adds the message body to the message
    */
    public Body(msg: Uint8Array): SMTPMessage {
        return this;
    }
    

    /**
    * Auth when called authenticates using username and password before sending the message
    */
    public Auth(username: string): SMTPMessage {
        return this;
    }
    

    /**
    * String returns the string representation of the message
    */
    public String(): string {
        return "";
    }
    

}



/**
 * IsSMTPResponse interface
 */
export interface IsSMTPResponse {
    
    IsSMTP?: boolean,
    
    Banner?: string,
}

