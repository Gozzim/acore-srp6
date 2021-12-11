import { createHash, Hash, randomBytes } from 'crypto';
import { BigInteger } from 'jsbn';

export interface SRP6Params {
  g: BigInteger;
  N: BigInteger;
  hash_alg: string;
  k: BigInteger;
}

const SRP6Params: SRP6Params = {
  g: new BigInteger('07', 16),
  N: new BigInteger('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16), // prettier-ignore
  hash_alg: 'sha1',
  k: new BigInteger('03', 16),
};

/**
 * TODO:
 *  - CleanUp
 *  - ErrorHandling
 *  - Documentation
 */

class SRP6 {
  protected readonly g: BigInteger;
  protected readonly N: BigInteger;
  protected readonly hash_alg: string;
  protected readonly k: BigInteger;

  protected ephemeralSeed: BigInteger | undefined;
  private _clientEphemeralKey: BigInteger | undefined;
  private _serverEphemeralKey: BigInteger | undefined;
  public sessionKey: BigInteger | undefined;

  protected username: string;
  private _verifier: Buffer | undefined;
  private _salt: Buffer | undefined;

  constructor(username: string, salt?: Buffer) {
    this.g = SRP6Params.g;
    this.N = SRP6Params.N;
    this.hash_alg = SRP6Params.hash_alg;
    this.k = SRP6Params.k;
    this.username = username;
    this.salt = salt;
  }

  get salt(): Buffer {
    if (!this._salt) {
      throw new Error('Salt not defined')
    }

    return this._salt;
  }

  set salt(value: Buffer) {
    this._salt = value;
  }

  get clientEphemeralKey(): BigInteger{
    if (!this._clientEphemeralKey) {
      throw new Error('Client Ephemeral Key not defined')
    }

    return this._clientEphemeralKey;
  }

  set clientEphemeralKey(value: BigInteger) {
    this._clientEphemeralKey = value;
  }

  get serverEphemeralKey(): BigInteger {
    if (!this._serverEphemeralKey) {
      throw new Error('Server Ephemeral Key not defined')
    }

    return this._serverEphemeralKey;
  }

  set serverEphemeralKey(value: BigInteger) {
    this._serverEphemeralKey = value;
  }

  get verifier(): Buffer {
    if (!this._verifier) {
      throw new Error('Verifier not defined')
    }

    return this._verifier;
  }

  set verifier(value: Buffer) {
    this._verifier = value;
  }

  public bnToHex(bn: BigInteger): string {
    let hex = BigInt(bn).toString(16);

    if (hex.length % 2) {
      hex = '0' + hex;
    }

    return hex;
  }

  public generateEphemeralSeed(): BigInteger {
    const rndHex = randomBytes(16).toString('hex');

    return new BigInteger(rndHex, 16);
  }

  public createSHA(type: string): Hash {
    switch (type) {
      case 'sha1':
        return createHash('sha1');
      case 'sha256':
        return createHash('sha256');
      case 'sha512':
        return createHash('sha512');
      default:
        throw new Error('Invalid hash algorithm');
    }
  }

  public sha(...values: (Buffer | string | BigInteger)[]): Buffer {
    const hash = this.createSHA(this.hash_alg);

    values.forEach((value) =>
      value instanceof BigInteger
        ? hash.update(this.bnToHex(value))
        : hash.update(value),
    );

    return hash.digest();
  }

  public xor(x: Buffer, y: Buffer): Buffer {
    return Buffer.from(x.map((v: number, i: number) => v ^ y[i]));
  }

  protected computeScrambleParam(): BigInteger {
    if (!this.clientEphemeralKey || !this.serverEphemeralKey) {
      throw new Error('Required values not found');
    }

    const u = this.sha(
      this.clientEphemeralKey,
      this.serverEphemeralKey,
    ).toString('hex');

    return new BigInteger(u, 16);
  }

  public computeClientProof(): string {
    if (!this.sessionKey) {
      throw new Error('Session Key not defined')
    }

    const A = this.clientEphemeralKey;
    const B = this.serverEphemeralKey;
    const I = this.sha(this.username);
    const s = this.salt;
    //const s = Buffer.from('12ee32e201835ebc6a00c7056f08e18651633ab9cec6cfd5a1bdda413747c74c')
    //const s = Buffer.from('7946D851555C9301CD6C36BC4D8535B3DF93F0D4CAC2923C917923DC0B4C75B8')
    const K = this.sha(this.sessionKey);

    const altS = K
    //const altS = this.toArray(this.sessionKey);
    //const altS = this.toArray(new BigInteger(K.toString('hex'), 16))
    const S1 = [];
    const S2 = [];
    for (let i = 0; i < 16; ++i) {
      S1[i] = altS[i * 2];
      S2[i] = altS[i * 2 + 1];
    }
    const S1h = this.sha(Buffer.from(S1));
    const S2h = this.sha(Buffer.from(S2));
    const altK = [];
    for (let i = 0; i < 20; ++i) {
      altK[i * 2] = S1h[i];
      altK[i * 2 + 1] = S2h[i];
    }
    const K2 = Buffer.from(altK);
    //console.log('altK', K2.toString('hex'))
    //console.log('hashedAltK', this.sha(K2).toString('hex'))
    //console.log('K', K.toString('hex'))

    const shaN = this.sha(this.N);
    const shag = this.sha(this.g);
    const shaNg = this.xor(shaN, shag);

    const proof = this.sha(shaNg, I, s, A, B, K);

    return proof.toString('hex');
  }

  public computeServerProof(M1: BigInteger): string {
    if (!this.sessionKey) {
      throw new Error('Session Key not defined')
    }

    const A = this.clientEphemeralKey;
    const K = this.sha(this.sessionKey);

    const proof = this.sha(A, M1, K);

    return proof.toString('hex');
  }

  public toArray(bi: BigInteger, littleEndian = true, unsigned = true) {
    const ba = bi.toByteArray();

    if (unsigned && bi.s === 0 && ba[0] === 0) {
      ba.shift();
    }

    if (littleEndian) {
      return ba.reverse();
    }

    return ba;
  }

  public fromArray(bytes: any, littleEndian = true, unsigned = true) {
    if (typeof bytes.toArray !== 'undefined') {
      bytes = bytes.toArray();
    } else {
      bytes = bytes.slice(0);
    }

    if (littleEndian) {
      bytes = bytes.reverse();
    }

    if (unsigned && bytes[0] & 0x80) {
      bytes.unshift(0);
    }

    return new BigInteger(bytes);
  }

  public constantTimeEq(a: Buffer, b: Buffer) {
    if (a.length !== b.length) {
      return false;
    }

    let c = 0;
    for (let i = 0; i < a.length; i++) {
      c |= a[i] ^ b[i];
      //console.log(a[i] ^ b[i])
    }
    return c;
  }

  public checkXor(a: Buffer, b: Buffer) {
    if (a.length !== b.length) {
      return false;
    }

    let c = [];
    for (let i = 0; i < a.length; i++) {
      c[i] = a[i] ^ b[i];
    }
    return c;
  }
}

export default SRP6;
