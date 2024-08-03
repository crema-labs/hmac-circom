import crypto from "crypto";

// reference https://datatracker.ietf.org/doc/html/rfc2104

export default class HMAC {
  static blockSize: number = 64;
  static innerPadding: number = 0x36;
  static outerPadding: number = 0x5c;

  static sha256(key: string | Buffer, message: string | Buffer): string {
    return this.hmac(key, message, "sha256");
  }

  static sha1(key: string | Buffer, message: string | Buffer): string {
    return this.hmac(key, message, "sha1");
  }

  static key_prep(key: string | Buffer, algorithm: "sha256" | "sha1") {
    let keyBuffer = Buffer.isBuffer(key) ? key : Buffer.from(key, "utf8");

    if (keyBuffer.length > this.blockSize) {
      keyBuffer = crypto.createHash(algorithm).update(keyBuffer).digest();
    }

    if (keyBuffer.length < this.blockSize) {
      const newBuffer = Buffer.alloc(this.blockSize);
      keyBuffer.copy(newBuffer);
      keyBuffer = newBuffer;
    }

    return keyBuffer;
  }
  static hmac(key: string | Buffer, message: string | Buffer, algorithm: "sha256" | "sha1"): string {
    let keyBuffer = this.key_prep(key, algorithm);
    let messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message, "utf8");

    const innerKey = Buffer.alloc(this.blockSize);
    const outerKey = Buffer.alloc(this.blockSize);

    for (let i = 0; i < this.blockSize; i++) {
      innerKey[i] = keyBuffer[i] ^ this.innerPadding;
      outerKey[i] = keyBuffer[i] ^ this.outerPadding;
    }

    const concatInner = Buffer.concat([innerKey, messageBuffer]);
    const innerHash = crypto.createHash(algorithm).update(concatInner).digest();
    const hmac = crypto.createHash(algorithm).update(outerKey).update(innerHash).digest("hex");

    return hmac;
  }
}
