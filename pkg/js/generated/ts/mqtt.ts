
/**
 * IsMQTT checks whether the target host:port is running an MQTT broker.
 * @example
 * ```javascript
 * const mqtt = require('nuclei/mqtt');
 * const isMqtt = mqtt.IsMQTT('acme.com', 1883);
 * log(isMqtt);
 * ```
 */
export function IsMQTT(host: string, port: number): boolean | null {
    return null;
}

/**
 * IsAnonymousAllowed checks whether an MQTT broker permits unauthenticated / anonymous login.
 * @example
 * ```javascript
 * const mqtt = require('nuclei/mqtt');
 * const allowed = mqtt.IsAnonymousAllowed('acme.com', 1883);
 * log(allowed);
 * ```
 */
export function IsAnonymousAllowed(host: string, port: number): boolean | null {
    return null;
}

/**
 * Message represents an MQTT published message.
 * @example
 * ```javascript
 * const mqtt = require('nuclei/mqtt');
 * const client = new mqtt.Client();
 * client.Connect('broker.hivemq.com', 1883);
 * const msgs = client.Subscribe('test/topic', 2);
 * log(msgs[0].Topic, msgs[0].Payload);
 * ```
 */
export interface Message {
    Topic?: string;
    Payload?: string;
    QoS?: number;
    Retain?: boolean;
}

/**
 * ConnectOptions contains connection options for an MQTT broker.
 * @example
 * ```javascript
 * const mqtt = require('nuclei/mqtt');
 * const opts = new mqtt.ConnectOptions();
 * opts.Username = 'admin';
 * opts.Password = 'admin';
 * opts.CleanSession = true;
 * ```
 */
export interface ConnectOptions {
    Username?: string;
    Password?: string;
    ClientID?: string;
    CleanSession?: boolean;
    KeepAlive?: number;
    TLS?: boolean;
    InsecureSkipVerify?: boolean;
    Timeout?: number;
}

/**
 * ConnectResult is the response returned by an MQTT connection attempt.
 * @example
 * ```javascript
 * const mqtt = require('nuclei/mqtt');
 * const client = new mqtt.Client();
 * const res = client.Connect('acme.com', 1883);
 * log(res.Success, res.ReturnCode, res.Reason);
 * ```
 */
export interface ConnectResult {
    Success?: boolean;
    ReturnCode?: number;
    Reason?: string;
    SessionPresent?: boolean;
}

/**
 * Client is an MQTT client for testing MQTT broker misconfigurations and authentication.
 * @example
 * ```javascript
 * const mqtt = require('nuclei/mqtt');
 * const client = new mqtt.Client();
 * const res = client.Connect('acme.com', 1883);
 * if (res.Success) {
 *     const msgs = client.Subscribe('#', 2);
 *     client.Publish('nuclei/probe', 'test');
 * }
 * client.Close();
 * ```
 */
export class Client {
    constructor() {}

    /**
     * Connect connects to an MQTT broker using optional credentials and settings.
     * @example
     * ```javascript
     * const mqtt = require('nuclei/mqtt');
     * const client = new mqtt.Client();
     * const res = client.Connect('acme.com', 1883);
     * log(res.Success);
     * ```
     */
    public Connect(host: string, port: number, options?: ConnectOptions): ConnectResult | null {
        return null;
    }

    /**
     * ConnectAuth connects to an MQTT broker with a username and password.
     * @example
     * ```javascript
     * const mqtt = require('nuclei/mqtt');
     * const client = new mqtt.Client();
     * const res = client.ConnectAuth('acme.com', 1883, 'admin', 'admin');
     * log(res.Success);
     * ```
     */
    public ConnectAuth(host: string, port: number, username: string, password: string): ConnectResult | null {
        return null;
    }

    /**
     * Subscribe subscribes to a topic filter and collects received messages up to timeoutSec.
     * @example
     * ```javascript
     * const mqtt = require('nuclei/mqtt');
     * const client = new mqtt.Client();
     * client.Connect('acme.com', 1883);
     * const msgs = client.Subscribe('#', 3);
     * for (const m of msgs) {
     *     log(m.Topic, m.Payload);
     * }
     * ```
     */
    public Subscribe(topic: string, timeoutSec?: number): Message[] | null {
        return null;
    }

    /**
     * Publish publishes a message payload to a topic.
     * @example
     * ```javascript
     * const mqtt = require('nuclei/mqtt');
     * const client = new mqtt.Client();
     * client.Connect('acme.com', 1883);
     * const ok = client.Publish('nuclei/test', 'probe payload');
     * log(ok);
     * ```
     */
    public Publish(topic: string, payload: string): boolean | null {
        return null;
    }

    /**
     * Ping sends an MQTT PINGREQ and awaits PINGRESP.
     * @example
     * ```javascript
     * const mqtt = require('nuclei/mqtt');
     * const client = new mqtt.Client();
     * client.Connect('acme.com', 1883);
     * const alive = client.Ping();
     * log(alive);
     * ```
     */
    public Ping(): boolean | null {
        return null;
    }

    /**
     * Close cleanly disconnects and closes the connection.
     * @example
     * ```javascript
     * const mqtt = require('nuclei/mqtt');
     * const client = new mqtt.Client();
     * client.Connect('acme.com', 1883);
     * client.Close();
     * ```
     */
    public Close(): error | null {
        return null;
    }
}
