import assert from "assert";
import HMAC from "../src/hmac";

// tests are taken from  https://datatracker.ietf.org/doc/html/rfc4231#section-4
describe("Ts_Hmac", () => {
  describe("RFC 4231 Test Vectors", () => {
    it("should pass RFC 4231 test vector 1 for SHA256", () => {
      let key = Buffer.from("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "hex");
      let message = "Hi There";
      let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
      let result = HMAC.sha256(key, message);
      assert.strictEqual(result, expected);
    });

    it("should pass RFC 4231 test vector 2 for SHA256", () => {
      let key = "Jefe";
      let message = "what do ya want for nothing?";
      let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
      let result = HMAC.sha256(key, message);
      assert.strictEqual(result, expected);
    });

    it("should pass RFC 4231 test vector 3 for SHA256", () => {
      let key = Buffer.from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hex");
      let message = Buffer.from(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "hex"
      );
      let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
      let result = HMAC.sha256(key, message);
      assert.strictEqual(result, expected);
    });

    it("should pass RFC 4231 test vector 4 for SHA256", () => {
      let key = Buffer.from("0102030405060708090a0b0c0d0e0f10111213141516171819", "hex");
      let message = Buffer.from(
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "hex"
      );
      let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";
      let result = HMAC.sha256(key, message);
      assert.strictEqual(result, expected);
    });

    it("should pass RFC 4231 test vector 5 for SHA256", () => {
      let key = Buffer.from("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "hex");
      let message = "Test With Truncation";
      let expected = "a3b6167473100ee06e0c796c2955552b";
      let result = HMAC.sha256(key, message).slice(0, 32); // Truncated to 128 bits
      assert.strictEqual(result, expected);
    });

    it("should pass RFC 4231 test vector 6 for SHA256", () => {
      let key = Buffer.from(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "hex"
      );
      let message = "Test Using Larger Than Block-Size Key - Hash Key First";
      let expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
      let result = HMAC.sha256(key, message);
      assert.strictEqual(result, expected);
    });

    it("should pass RFC 4231 test vector 7 for SHA256", () => {
      let key = Buffer.from(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "hex"
      );
      let message =
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
      let expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";
      let result = HMAC.sha256(key, message);
      assert.strictEqual(result, expected);
    });
  });
});
