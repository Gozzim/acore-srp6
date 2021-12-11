import SRP6 from './srp6';
import { BigInteger } from 'jsbn';

class SRP6Server extends SRP6 {
  constructor(username: string, salt?: Buffer) {
    super(username, salt);
  }

  public computeEphemeralKey(): void {
    const b = this.generateEphemeralSeed();
    //const b = new BigInteger('d5e3b01f32f6eed10d8e3ffb98f28b95', 16);
    const v = new BigInteger(this.verifier.toString('hex'), 16)
    // B = kv + g^b mod N
    this.serverEphemeralKey = this.k.multiply(v).add(this.g.modPow(b, this.N)).mod(this.N); //while (!publicValue || publicValue.mod(this.N).intValue() === 0)
    this.ephemeralSeed = b;
  }

  public computeSessionKey(): void {
    const A = this.clientEphemeralKey;
    const b = this.ephemeralSeed;
    const v = new BigInteger(this.verifier.toString('hex'), 16);
    const N = this.N;

    // Random scrambling parameter
    const u = this.computeScrambleParam();
    // Session Key S = (Av^u) ^ b
    const S = A.multiply(v.modPow(u, N)).modPow(b, N);
    console.log(this.bnToHex(S))
    console.log(this.sha(S).toString('hex'))

    this.sessionKey = S;
  }

  public validateProof(proof: string): boolean {
    const check = this.computeClientProof();

    return check === proof;
  }
}

export default SRP6Server;
