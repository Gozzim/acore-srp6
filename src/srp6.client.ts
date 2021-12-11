import { randomBytes } from 'crypto';
import { BigInteger } from 'jsbn';
import SRP6 from './srp6';

class SRP6Client extends SRP6 {
  private privateKey: BigInteger | undefined;
  constructor(username: string, salt?: Buffer) {
    super(username, salt);
  }

  /**
   * Generate User Salt
   * @param {number} length
   * @returns {Buffer} User Salt
   */
  public generateSalt(length = 32): string {
    return randomBytes(length).toString('hex');
  }

  private async computePrivateKey (
    username: string,
    password: string,
    salt: Buffer
  ): Promise<BigInteger> {
    const h1 = this.sha(`${username}:${password}`.toUpperCase());
    const h2 = this.sha(salt, h1).reverse();

    return new BigInteger(h2.toString('hex'), 16);
  }

  public async computeVerifier(password: string): Promise<Buffer> {
    this.privateKey = await this.computePrivateKey(this.username, password, this.salt);
    const verifier = this.g.modPow(this.privateKey, this.N);

    return Buffer.from(this.bnToHex(verifier), 'hex').reverse();
  }

  public computeEphemeralKey(): void {
    const a = this.generateEphemeralSeed();
    //const a = new BigInteger('e49bbcf11482262ab646feb4c554c196', 16);
    // A = g^a mod N
    this.clientEphemeralKey = this.g.modPow(a, this.N); //while (!publicValue || publicValue.mod(this.N).intValue() === 0)
    this.ephemeralSeed = a;
  }

  public computeSessionKey(): void {
    const B = this.serverEphemeralKey;
    const a = this.ephemeralSeed;
    const v = new BigInteger(this.verifier.toString('hex'), 16);
    const N = this.N;
    const k = this.k;
    const x = this.privateKey;
    //const x = new BigInteger('bd037a6568827250f8aeaf68f6d44e8d66f16099', 16)
    if (!x) {
      throw new Error('Private Key not defined')
    }

    // Random scrambling parameter
    const u = this.computeScrambleParam();
    // Session Key S = (B - (kg^x)) ^ (a + ux)
    const S = B.subtract(k.multiply(v)).modPow(a.add(u.multiply(x)), N)
    console.log(this.bnToHex(S))
    console.log(this.sha(S).toString('hex'))
    console.log('x', this.bnToHex(x))

    this.sessionKey = S;
  }

  public validateProof(M1: BigInteger, proof: string): boolean {
    const check = this.computeServerProof(M1);

    return check === proof;
  }
}

export default SRP6Client;
