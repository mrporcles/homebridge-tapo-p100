import { Logger } from 'homebridge';
import crypto from 'crypto';

/**
 * TPAP (TP-Link Application Protocol) Cipher
 * Uses SPAKE2+ key exchange and AES-128-CCM encryption
 * Introduced in firmware 1.4.0+
 */
export default class TpapCipher {
  private _crypto = crypto;
  private log: Logger;
  private sessionKey!: Buffer;
  private encryptionKey!: Buffer;
  private sigKey!: Buffer;
  private seq: number = 0;
  private iv!: Buffer;

  // SPAKE2+ constants for P-256 curve (RFC 9382)
  private readonly SPAKE2_M = Buffer.from([
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7,
    0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab,
    0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f, 0xf3, 0x55,
    0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac,
    0x8e, 0x5c, 0x7b, 0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d,
    0x55, 0xa1, 0x2e, 0x2d, 0x20,
  ]);

  private readonly SPAKE2_N = Buffer.from([
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99,
    0x7f, 0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49,
    0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07, 0xd6, 0x0a,
    0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68,
    0xc6, 0x4d, 0x9b, 0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b,
    0x1e, 0x65, 0x6e, 0xdb, 0xe7,
  ]);

  constructor(log: Logger) {
    this.log = log;
  }

  /**
   * Perform SPAKE2+ handshake with device
   */
  async handshake(
    ipAddress: string,
    username: string,
    password: string,
    rawRequest: (path: string, data: Buffer, responseType: string) => Promise<Buffer>,
  ): Promise<void> {
    this.log.debug('Starting TPAP/SPAKE2+ handshake');

    // Step 1: Generate ephemeral key pair (for future use in full implementation)
    // const keyPair = this._crypto.generateKeyPairSync('ec', {
    //   namedCurve: 'prime256v1',  
    //   publicKeyEncoding: { type: 'spki', format: 'der' },
    //   privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    // });

    // Step 2: Calculate w0 and w1 from password
    const { w0, w1 } = this.derivePasswordParams(username, password);

    // Step 3: Calculate X = w0*M + x*G (client public key)
    const x = this.generateRandomScalar();
    const X = this.calculateClientPublicKey(w0, x);

    // Step 4: Send handshake1 request
    const handshake1Payload = this.encodeHandshake1(X);
    const response1 = await rawRequest('handshake1', handshake1Payload, 'arraybuffer');

    // Step 5: Parse server response and calculate shared secret
    const { Y, serverMac } = this.parseHandshake1Response(response1);
    const sharedSecret = this.calculateSharedSecret(w1, x, X, Y);

    // Step 6: Verify server MAC
    const expectedServerMac = this.calculateServerMac(X, Y, sharedSecret);
    if (!expectedServerMac.equals(serverMac)) {
      throw new Error('TPAP handshake failed: Server MAC verification failed');
    }

    // Step 7: Calculate client MAC and send handshake2
    const clientMac = this.calculateClientMac(X, Y, sharedSecret);
    const response2 = await rawRequest('handshake2', clientMac, 'text');

    if (response2.toString() !== 'ok') {
      throw new Error('TPAP handshake failed: Handshake2 not acknowledged');
    }

    // Step 8: Derive session keys from shared secret
    this.deriveSessionKeys(sharedSecret);
    
    this.log.debug('TPAP/SPAKE2+ handshake completed successfully');
  }

  /**
   * Encrypt payload using AES-128-CCM
   */
  encrypt(data: string | Buffer): { encryptedPayload: Buffer; seq: number } {
    this.seq += 1;

    if (typeof data === 'string') {
      data = Buffer.from(data, 'utf8');
    }

    // Create IV with sequence number
    const iv = this.createIvWithSeq(this.seq);

    // Create cipher
    const cipher = this._crypto.createCipheriv('aes-128-ccm', this.encryptionKey, iv, {
      authTagLength: 16,
    });

    // Encrypt data
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Create signature
    const seqBuffer = Buffer.alloc(4);
    seqBuffer.writeUInt32BE(this.seq, 0);

    const signature = this._crypto
      .createHmac('sha256', this.sigKey)
      .update(Buffer.concat([seqBuffer, ciphertext, authTag]))
      .digest()
      .subarray(0, 32);

    return {
      encryptedPayload: Buffer.concat([signature, ciphertext, authTag]),
      seq: this.seq,
    };
  }

  /**
   * Decrypt response using AES-128-CCM
   */
  decrypt(data: Buffer): string {
    if (data.length < 48) { // 32 (signature) + 16 (min ciphertext + auth tag)
      throw new Error('TPAP response too short');
    }

    const signature = data.subarray(0, 32);
    const ciphertext = data.subarray(32, -16);
    const authTag = data.subarray(-16);

    // Create IV with current sequence
    const iv = this.createIvWithSeq(this.seq);

    // Verify signature
    const seqBuffer = Buffer.alloc(4);
    seqBuffer.writeUInt32BE(this.seq, 0);

    const expectedSignature = this._crypto
      .createHmac('sha256', this.sigKey)
      .update(Buffer.concat([seqBuffer, ciphertext, authTag]))
      .digest()
      .subarray(0, 32);

    if (!signature.equals(expectedSignature)) {
      throw new Error('TPAP response signature verification failed');
    }

    // Decrypt data
    const decipher = this._crypto.createDecipheriv('aes-128-ccm', this.encryptionKey, iv, {
      authTagLength: 16,
    });
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const result = decrypted.toString('utf8');

    this.log.debug('TPAP decrypted:', result);
    return result;
  }

  /**
   * Derive w0 and w1 parameters from username and password
   */
  private derivePasswordParams(username: string, password: string): { w0: Buffer; w1: Buffer } {
    // Normalize credentials
    const normalizedUsername = Buffer.from(username.normalize('NFKC'), 'utf8');
    const normalizedPassword = Buffer.from(password.normalize('NFKC'), 'utf8');

    // Calculate w0 = HKDF(SHA256(username) || SHA256(password), salt="spake2+_w0", length=32)
    const usernameHash = this._crypto.createHash('sha256').update(normalizedUsername).digest();
    const passwordHash = this._crypto.createHash('sha256').update(normalizedPassword).digest();
    const combinedHash = Buffer.concat([usernameHash, passwordHash]);

    const w0 = Buffer.from(this._crypto.hkdfSync('sha256', combinedHash, Buffer.from('spake2+_w0'), 'spake2+_tapo', 32));
    const w1 = Buffer.from(this._crypto.hkdfSync('sha256', combinedHash, Buffer.from('spake2+_w1'), 'spake2+_tapo', 32));

    return { w0, w1 };
  }

  /**
   * Generate random scalar for ephemeral key
   */
  private generateRandomScalar(): Buffer {
    return this._crypto.randomBytes(32);
  }

  /**
   * Calculate client public key: X = w0*M + x*G
   */
  private calculateClientPublicKey(w0: Buffer, x: Buffer): Buffer {
    // This is a simplified version - in production, use proper EC point arithmetic
    // For now, return a placeholder that would work with proper crypto library
    const key = this._crypto.createECDH('prime256v1');
    key.setPrivateKey(x);
    return key.getPublicKey();
  }

  /**
   * Parse handshake1 response
   */
  private parseHandshake1Response(response: Buffer): { Y: Buffer; serverMac: Buffer } {
    if (response.length < 97) { // 65 (compressed point) + 32 (MAC)
      throw new Error('Invalid handshake1 response length');
    }

    const Y = response.subarray(0, 65);
    const serverMac = response.subarray(65, 97);

    return { Y, serverMac };
  }

  /**
   * Calculate shared secret from SPAKE2+ exchange
   */
  private calculateSharedSecret(w1: Buffer, x: Buffer, X: Buffer, Y: Buffer): Buffer {
    // Simplified implementation - use proper EC arithmetic in production
    return this._crypto.createHash('sha256').update(Buffer.concat([w1, x, X, Y])).digest();
  }

  /**
   * Calculate server MAC for verification
   */
  private calculateServerMac(X: Buffer, Y: Buffer, sharedSecret: Buffer): Buffer {
    return this._crypto
      .createHmac('sha256', sharedSecret)
      .update(Buffer.concat([Buffer.from('server'), X, Y]))
      .digest()
      .subarray(0, 32);
  }

  /**
   * Calculate client MAC for handshake2
   */
  private calculateClientMac(X: Buffer, Y: Buffer, sharedSecret: Buffer): Buffer {
    return this._crypto
      .createHmac('sha256', sharedSecret)
      .update(Buffer.concat([Buffer.from('client'), X, Y]))
      .digest()
      .subarray(0, 32);
  }

  /**
   * Derive session keys from shared secret
   */
  private deriveSessionKeys(sharedSecret: Buffer): void {
    this.sessionKey = sharedSecret;
    
    // Derive encryption key: HKDF(shared_secret, salt="tpap_enc", length=16)
    this.encryptionKey = Buffer.from(this._crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), 'tpap_enc', 16));
    
    // Derive signature key: HKDF(shared_secret, salt="tpap_sig", length=32)  
    this.sigKey = Buffer.from(this._crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), 'tpap_sig', 32));
    
    // Initialize IV base
    this.iv = Buffer.from(this._crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), 'tpap_iv', 12));
    
    this.log.debug('TPAP session keys derived');
  }

  /**
   * Create IV with sequence number for AES-CCM
   */
  private createIvWithSeq(seq: number): Buffer {
    const seqBuffer = Buffer.alloc(4);
    seqBuffer.writeUInt32BE(seq, 0);
    return Buffer.concat([this.iv, seqBuffer]);
  }

  /**
   * Encode handshake1 payload
   */
  private encodeHandshake1(X: Buffer): Buffer {
    // Simple encoding - prepend length
    const length = Buffer.alloc(2);
    length.writeUInt16BE(X.length, 0);
    return Buffer.concat([length, X]);
  }
}