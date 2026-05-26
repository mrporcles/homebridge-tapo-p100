import { Logger } from 'homebridge';
import crypto from 'crypto';
import axios, { AxiosInstance, AxiosResponse } from 'axios';
import https from 'https';

// SPAKE2+ constants for P-256 curve (RFC 9382) - reserved for full implementation
// const P256_M = Buffer.from('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f', 'hex');
// const P256_N = Buffer.from('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49', 'hex');
const PAKE_CTX = Buffer.from('PAKE V1');

// Cipher configuration
const CIPHER_LABELS = {
  aes_128_ccm: {
    ks: Buffer.from('tp-kdf-salt-aes128-key'),
    ki: Buffer.from('tp-kdf-info-aes128-key'),
    ns: Buffer.from('tp-kdf-salt-aes128-iv'),
    ni: Buffer.from('tp-kdf-info-aes128-iv'),
    kl: 16,
  },
  aes_256_ccm: {
    ks: Buffer.from('tp-kdf-salt-aes256-key'),
    ki: Buffer.from('tp-kdf-info-aes256-key'),
    ns: Buffer.from('tp-kdf-salt-aes256-iv'),
    ni: Buffer.from('tp-kdf-info-aes256-iv'),
    kl: 32,
  },
  chacha20_poly1305: {
    ks: Buffer.from('tp-kdf-salt-chacha20-key'),
    ki: Buffer.from('tp-kdf-info-chacha20-key'),
    ns: Buffer.from('tp-kdf-salt-chacha20-iv'),
    ni: Buffer.from('tp-kdf-info-chacha20-iv'),
    kl: 32,
  },
};

const NONCE_LEN = 12;

interface TpapDiscoverResult {
  mac?: string;
  tpap?: {
    pake?: number[];
  };
}

interface TpapRegisterResult {
  cipher_suites?: number;
  iterations?: number;
  encryption?: string;
  dev_salt: string;
  dev_share: string;
  dev_random: string;
  extra_crypt?: {
    type?: string;
    params?: Record<string, unknown>;
  };
}

interface TpapShareResult {
  sessionId?: string;
  stok?: string;
  start_seq?: number;
  dev_confirm?: string;
}

export default class TpapCipher {
  private _crypto: typeof crypto;
  private log: Logger;
  private host: string;
  private port: number;
  private username: string;
  private password: string;
  private _axios: AxiosInstance;
  
  // Session state
  private deviceMac: string = '';
  private tpapPake: number[] = [];
  private sessionId: string = '';
  private seq: number = 1;
  private cipherId: string = 'aes_128_ccm';
  private hkdfHash: string = 'SHA256';
  private key: Buffer = Buffer.alloc(0);
  private baseNonce: Buffer = Buffer.alloc(0);

  constructor(host: string, username: string, password: string, log: Logger, port: number = 443) {
    this._crypto = crypto;
    this.log = log;
    this.host = host;
    this.port = port;
    this.username = username;
    this.password = password;
    
    // Create HTTPS axios instance with SSL verification disabled (like the Python implementation)
    this._axios = axios.create({
      baseURL: `https://${host}:${port}`,
      timeout: 15000,
      httpsAgent: new https.Agent({
        rejectUnauthorized: false, // Disable SSL verification for Tapo devices
      }),
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * Perform complete TPAP handshake (discover + pake_register + pake_share)
   * Based on the working Python implementation from tapo-rv30-ha
   */
  async handshake(): Promise<void> {
    this.log.info('🔐 Starting TPAP/SPAKE2+ handshake on HTTPS port 443');

    try {
      // Step 1: Discover device capabilities
      await this.discover();
      
      // Step 2: Perform SPAKE2+ authentication
      await this.authenticate();
      
      this.log.info('✅ TPAP handshake completed successfully');
    } catch (error) {
      this.log.error('❌ TPAP handshake failed:', (error as Error).message);
      throw error;
    }
  }

  /**
   * Step 1: Discover device capabilities and TPAP support
   */
  private async discover(): Promise<void> {
    this.log.debug('TPAP: Sending discover request');
    
    const response = await this.post('/', {
      method: 'login',
      params: {
        sub_method: 'discover',
      },
    });

    const result = response.result as TpapDiscoverResult;
    this.deviceMac = result.mac || '';
    this.tpapPake = result.tpap?.pake || [];
    
    this.log.debug(`TPAP: Device MAC: ${this.deviceMac}, PAKE support: [${this.tpapPake.join(', ')}]`);
  }

  /**
   * Step 2: Perform SPAKE2+ authentication (pake_register + pake_share)
   */
  private async authenticate(): Promise<void> {
    // Determine passcode type based on PAKE support
    const ptype = this.tpapPake.includes(0) ? 'default_userpw' :
      this.tpapPake.includes(2) ? 'userpw' :
        this.tpapPake.includes(3) ? 'shared_token' : 'userpw';

    const userRandom = this._crypto.randomBytes(32);

    // Step 2a: pake_register
    this.log.debug('TPAP: Sending pake_register request');
    const registerResponse = await this.post('/', {
      method: 'login',
      params: {
        sub_method: 'pake_register',
        username: this.md5hex('admin'),
        user_random: userRandom.toString('base64'),
        cipher_suites: [1],
        encryption: ['aes_128_ccm', 'chacha20_poly1305', 'aes_256_ccm'],
        passcode_type: ptype,
        stok: null,
      },
    });

    if (registerResponse.error_code !== 0) {
      throw new Error(`TPAP pake_register failed with error code: ${registerResponse.error_code}`);
    }

    const registerResult = registerResponse.result as TpapRegisterResult;

    // Configure cipher suite and parameters
    const suiteType = registerResult.cipher_suites || 2;
    const iterations = registerResult.iterations || 10000;
    this.cipherId = (registerResult.encryption || 'aes_128_ccm').toLowerCase().replace('-', '_');
    this.hkdfHash = [2, 4, 5, 7, 9].includes(suiteType) ? 'SHA512' : 'SHA256';

    // Build credentials
    const mac12 = this.deviceMac.replace(/[:-]/g, '');
    const cred = this.buildCredentials(ptype, registerResult.extra_crypt, mac12);

    // Step 2b: Perform SPAKE2+ key exchange
    const { userShare, userConfirm, expectedDevConfirm, sharedSecret } = 
      await this.performSpake2Exchange(cred, registerResult, userRandom, iterations);

    // Step 2c: pake_share
    this.log.debug('TPAP: Sending pake_share request');
    const shareResponse = await this.post('/', {
      method: 'login',
      params: {
        sub_method: 'pake_share',
        user_share: userShare.toString('base64'),
        user_confirm: userConfirm.toString('base64'),
      },
    });

    if (shareResponse.error_code !== 0) {
      throw new Error(`TPAP pake_share failed with error code: ${shareResponse.error_code}`);
    }

    const shareResult = shareResponse.result as TpapShareResult;

    // Verify device confirmation
    if ((shareResult.dev_confirm || '').toLowerCase() !== expectedDevConfirm.toString('base64').toLowerCase()) {
      throw new Error('SPAKE2+ confirmation mismatch - wrong password?');
    }

    // Setup session
    this.sessionId = shareResult.sessionId || shareResult.stok || '';
    this.seq = shareResult.start_seq || 1;
    
    const { key, nonce } = this.deriveCipherKeys(sharedSecret);
    this.key = key;
    this.baseNonce = nonce;

    this.log.debug('TPAP: Session established successfully');
  }

  /**
   * Perform simplified SPAKE2+ exchange (basic implementation for proof of concept)
   */
  private async performSpake2Exchange(
    cred: string,
    registerResult: TpapRegisterResult,
    userRandom: Buffer,
    iterations: number,
  ): Promise<{
    userShare: Buffer;
    userConfirm: Buffer;
    expectedDevConfirm: Buffer;
    sharedSecret: Buffer;
  }> {
    // Simplified implementation for compatibility
    // In a full implementation, this would use proper SPAKE2+ elliptic curve cryptography
    
    const devSalt = Buffer.from(registerResult.dev_salt, 'base64');
    const devRandom = Buffer.from(registerResult.dev_random, 'base64');
    const devShare = Buffer.from(registerResult.dev_share, 'base64');
    
    // Generate PBKDF2 keys from credentials
    const dlen = this.hkdfHash === 'SHA512' ? 64 : 32;
    const derivedKey = this._crypto.pbkdf2Sync(cred, devSalt, iterations, dlen * 2, 'sha256');
    
    // Generate user key pair (simplified)
    const userPrivKey = this._crypto.createECDH('secp256r1');
    userPrivKey.generateKeys();
    const userShare = userPrivKey.getPublicKey();
    
    // Compute shared secret (simplified DH)
    try {
      const dhSecret = userPrivKey.computeSecret(devShare);
      
      // Generate transcript hash
      const transcript = this.sha256(Buffer.concat([
        PAKE_CTX,
        userRandom,
        devRandom,
        userShare,
        devShare,
        derivedKey,
      ]));
      
      // Generate confirmations (HMAC)
      const userConfirm = this._crypto.createHmac('sha256', derivedKey.subarray(0, 32))
        .update(Buffer.concat([devShare, transcript]))
        .digest()
        .subarray(0, 16);
        
      const expectedDevConfirm = this._crypto.createHmac('sha256', derivedKey.subarray(32, 64))
        .update(Buffer.concat([userShare, transcript]))
        .digest()
        .subarray(0, 16);
      
      // Derive final shared secret
      const sharedSecret = this.sha256(Buffer.concat([dhSecret, transcript]));
      
      return {
        userShare,
        userConfirm,
        expectedDevConfirm,
        sharedSecret,
      };
    } catch (error) {
      throw new Error(`SPAKE2+ key exchange failed: ${(error as Error).message}`);
    }
  }

  /**
   * Build credentials based on device capabilities
   */
  private buildCredentials(ptype: string, extraCrypt?: Record<string, unknown>, mac12?: string): string {
    if (ptype === 'default_userpw' && this.deviceMac) {
      return this.macPass(this.deviceMac);
    }

    if (extraCrypt?.type === 'password_shadow') {
      const params = extraCrypt.params as Record<string, unknown>;
      const passwdId = Number(params?.passwd_id || 0);
      
      if (passwdId === 2) {
        return this.sha1hex(this.password);
      }
      
      if (passwdId === 3 && this.username && mac12 && mac12.length === 12) {
        const mac = mac12.match(/.{2}/g)?.join(':').toUpperCase() || '';
        return this.sha1hex(this.md5hex(this.username) + '_' + mac);
      }
    }

    if (extraCrypt?.type === 'password_sha_with_salt') {
      const params = extraCrypt.params as Record<string, unknown>;
      const shaName = Number(params?.sha_name || -1);
      const name = shaName === 0 ? 'admin' : 'user';
      
      try {
        const salt = Buffer.from(String(params?.sha_salt || ''), 'base64').toString();
        return this._crypto.createHash('sha256').update(name + salt + this.password).digest('hex');
      } catch {
        return this.password;
      }
    }

    return this.username ? `${this.username}/${this.password}` : this.password;
  }

  /**
   * Derive cipher keys from shared secret
   */
  private deriveCipherKeys(sharedSecret: Buffer): { key: Buffer; nonce: Buffer } {
    const labels = CIPHER_LABELS[this.cipherId as keyof typeof CIPHER_LABELS];
    if (!labels) {
      throw new Error(`Unsupported cipher: ${this.cipherId}`);
    }

    const key = this.hkdf(sharedSecret, labels.ks, labels.ki, labels.kl);
    const nonce = this.hkdf(sharedSecret, labels.ns, labels.ni, NONCE_LEN);

    return { key, nonce };
  }

  /**
   * Send encrypted request to device
   */
  async sendRequest(method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    if (!this.sessionId) {
      throw new Error('No active TPAP session - call handshake() first');
    }

    const payload = JSON.stringify({ method, params });
    const encrypted = this.encrypt(payload);

    const data = Buffer.concat([
      Buffer.from([this.seq >> 24, this.seq >> 16, this.seq >> 8, this.seq]),
      encrypted,
    ]);

    const response = await this._axios.post(`/stok=${this.sessionId}/ds`, data, {
      headers: {
        'Content-Type': 'application/octet-stream',
      },
      responseType: 'arraybuffer',
    });

    const respData = Buffer.from(response.data as ArrayBuffer);
    if (respData.length < 4) {
      throw new Error(`Response too short (${respData.length}b)`);
    }

    const respSeq = respData.readUInt32BE(0);
    const decrypted = this.decrypt(respData.subarray(4), respSeq);
    
    this.seq++;

    const result = JSON.parse(decrypted);
    if (result.error_code !== 0) {
      throw new Error(`Device error ${result.error_code}: ${JSON.stringify(result)}`);
    }

    return result;
  }

  /**
   * Encrypt data using AES-128-CCM (simulated with GCM)
   */
  private encrypt(data: string | Buffer): Buffer {
    const plaintext = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    const nonce = this.getNonce(this.seq);
    
    const cipher = this._crypto.createCipheriv('aes-128-gcm', this.key, nonce);
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    
    const tag = cipher.getAuthTag();
    
    return Buffer.concat([encrypted, tag]);
  }

  /**
   * Decrypt data using AES-128-CCM (simulated with GCM)
   */
  private decrypt(data: Buffer, seq: number): string {
    if (data.length < 16) {
      throw new Error('Encrypted data too short');
    }
    
    const nonce = this.getNonce(seq);
    const ciphertext = data.subarray(0, -16);
    const tag = data.subarray(-16);
    
    const decipher = this._crypto.createDecipheriv('aes-128-gcm', this.key, nonce);
    decipher.setAuthTag(tag);
    
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    
    return decrypted.toString('utf8');
  }

  /**
   * Generate nonce for encryption
   */
  private getNonce(seq: number): Buffer {
    const nonce = Buffer.from(this.baseNonce);
    nonce.writeUInt32BE(seq, nonce.length - 4);
    return nonce;
  }

  // Utility methods
  private async post(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response: AxiosResponse = await this._axios.post(path, body);
    return response.data;
  }

  private md5hex(s: string): string {
    return this._crypto.createHash('md5').update(s).digest('hex');
  }

  private sha1hex(s: string): string {
    return this._crypto.createHash('sha1').update(s).digest('hex');
  }

  private sha256(data: Buffer): Buffer {
    return this._crypto.createHash('sha256').update(data).digest();
  }

  private sha512(data: Buffer): Buffer {
    return this._crypto.createHash('sha512').update(data).digest();
  }

  private hkdf(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
    const algorithm = this.hkdfHash === 'SHA512' ? 'sha512' : 'sha256';
    return Buffer.from(this._crypto.hkdfSync(algorithm, ikm, salt, info, length));
  }

  private hkdfExpand(label: string, prk: Buffer, length: number): Buffer {
    const algorithm = this.hkdfHash === 'SHA512' ? 'sha512' : 'sha256';
    const info = Buffer.from(label, 'utf8');
    return Buffer.from(this._crypto.hkdfSync(algorithm, prk, Buffer.alloc(length), info, length));
  }

  private cmacAes(key: Buffer, data: Buffer): Buffer {
    // Simplified CMAC implementation using HMAC for compatibility
    return this._crypto.createHmac('sha256', key).update(data).digest().subarray(0, 16);
  }

  private macPass(mac: string): string {
    const b = Buffer.from(mac.replace(/[:-]/g, ''), 'hex');
    const ikm = Buffer.concat([Buffer.from('GqY5o136oa4i6VprTlMW2DpVXxmfW8'), b.subarray(3, 6), b.subarray(0, 3)]);
    return this.hkdf(
      ikm,
      Buffer.from('tp-kdf-salt-default-passcode'),
      Buffer.from('tp-kdf-info-default-passcode'),
      32,
    ).toString('hex').toUpperCase();
  }

  private l8(b: Buffer): Buffer {
    const length = Buffer.alloc(8);
    length.writeUInt32LE(b.length, 0);
    return Buffer.concat([length, b]);
  }

  private encodeW(w: bigint): Buffer {
    const ml = w === 0n ? 1 : Math.ceil(w.toString(16).length / 2);
    const u = Buffer.from(w.toString(16).padStart(ml * 2, '0'), 'hex');
    return (ml % 2 !== 0 && u[0] & 0x80) ? Buffer.concat([Buffer.from([0x00]), u]) : u;
  }
}