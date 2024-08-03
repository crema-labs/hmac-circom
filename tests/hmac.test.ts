import { WitnessTester } from "circomkit";
import { circomkit } from "./common";
import HMAC from "../src/hmac";

describe("KeyPrep", () => {
  let circuit: WitnessTester<["in"], ["key"]>;

  it("should create correct key RFC 4231 test vector 1", async () => {
    let key = Buffer.from("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "hex");
    let expected_1 = Array.from(HMAC.key_prep(key, "sha256"));

    circuit = await circomkit.WitnessTester(`KeyPrep`, {
      file: "hmac",
      template: "KeyPrep",
      params: [key.length],
    });
    console.log("@KeyPrep #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ in: Array.from(key) }, { key: expected_1 });
  });

  it("should create correct key RFC 4231 test vector 2", async () => {
    let key = Buffer.from("Jefe", "utf8");
    let expected_1 = Array.from(HMAC.key_prep(key, "sha256"));

    circuit = await circomkit.WitnessTester(`KeyPrep`, {
      file: "hmac",
      template: "KeyPrep",
      params: [key.length],
    });
    console.log("@KeyPrep #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ in: Array.from(key) }, { key: expected_1 });
  });

  it("should create correct key RFC 4231 test vector 3", async () => {
    let key = Buffer.from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hex");
    let expected_1 = Array.from(HMAC.key_prep(key, "sha256"));

    circuit = await circomkit.WitnessTester(`KeyPrep`, {
      file: "hmac",
      template: "KeyPrep",
      params: [key.length],
    });
    console.log("@KeyPrep #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ in: Array.from(key) }, { key: expected_1 });
  });

  it("should create correct key RFC 4231 test vector 4", async () => {
    let key = Buffer.from("0102030405060708090a0b0c0d0e0f10111213141516171819", "hex");
    let expected_1 = Array.from(HMAC.key_prep(key, "sha256"));

    circuit = await circomkit.WitnessTester(`KeyPrep`, {
      file: "hmac",
      template: "KeyPrep",
      params: [key.length],
    });
    console.log("@KeyPrep #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ in: Array.from(key) }, { key: expected_1 });
  });
  it("should create correct key RFC 4231 test vector 5", async () => {
    let key = Buffer.from("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "hex");
    let expected_1 = Array.from(HMAC.key_prep(key, "sha256"));

    circuit = await circomkit.WitnessTester(`KeyPrep`, {
      file: "hmac",
      template: "KeyPrep",
      params: [key.length],
    });
    console.log("@KeyPrep #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ in: Array.from(key) }, { key: expected_1 });
  });

  it("should create correct key RFC 4231 test vector 6", async () => {
    let key = Buffer.from(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "hex"
    );
    let expected_1 = Array.from(HMAC.key_prep(key, "sha256"));

    circuit = await circomkit.WitnessTester(`KeyPrep`, {
      file: "hmac",
      template: "KeyPrep",
      params: [key.length],
    });
    console.log("@KeyPrep #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ in: Array.from(key) }, { key: expected_1 });
  });

  it("should create correct key RFC 4231 test vector 7", async () => {
    let key = Buffer.from(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "hex"
    );
    let expected_1 = Array.from(HMAC.key_prep(key, "sha256"));

    circuit = await circomkit.WitnessTester(`KeyPrep`, {
      file: "hmac",
      template: "KeyPrep",
      params: [key.length],
    });
    console.log("@KeyPrep #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ in: Array.from(key) }, { key: expected_1 });
  });
});

describe("Hmac", () => {
  let circuit: WitnessTester<["message", "key"], ["hmac"]>;

  it("should pass RFC 4231 test vector 1 for SHA256", async () => {
    let key = Array.from(Buffer.from("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "hex"));
    let message = Array.from(Buffer.from("Hi There", "utf8"));
    let expected = Array.from(Buffer.from("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "hex"));

    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "hmac",
      template: "HmacSha256",
      params: [message.length, key.length],
    });
    console.log("@Hmac #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ message, key }, { hmac: expected });
  });

  it("should pass RFC 4231 test vector 2 for SHA256", async () => {
    let key = Array.from(Buffer.from("Jefe", "utf8"));
    let message = Array.from(Buffer.from("what do ya want for nothing?", "utf8"));
    let expected = Array.from(Buffer.from("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "hex"));

    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "hmac",
      template: "HmacSha256",
      params: [message.length, key.length],
    });
    console.log("@Hmac #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ message, key }, { hmac: expected });
  });

  it("should pass RFC 4231 test vector 3 for SHA256", async () => {
    let key = Array.from(Buffer.from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hex"));
    let message = Array.from(
      Buffer.from(
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "hex"
      )
    );
    let expected = Array.from(Buffer.from("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", "hex"));
    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "hmac",
      template: "HmacSha256",
      params: [message.length, key.length],
    });
    console.log("@Hmac #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ message, key }, { hmac: expected });
  });

  it("should pass RFC 4231 test vector 4 for SHA256", async () => {
    let key = Array.from(Buffer.from("0102030405060708090a0b0c0d0e0f10111213141516171819", "hex"));
    let message = Array.from(
      Buffer.from(
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "hex"
      )
    );
    let expected = Array.from(Buffer.from("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", "hex"));
    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "hmac",
      template: "HmacSha256",
      params: [message.length, key.length],
    });
    console.log("@Hmac #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ message, key }, { hmac: expected });
  });

  it("should pass RFC 4231 test vector 4 for SHA256", async () => {
    let key = Array.from(Buffer.from("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "hex"));
    let expected = Array.from(Buffer.from("a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5", "hex"));
    let message = Array.from(Buffer.from("Test With Truncation", "utf8"));
    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "hmac",
      template: "HmacSha256",
      params: [message.length, key.length],
    });
    console.log("@Hmac #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ message, key }, { hmac: expected });
  });
  it("should pass RFC 4231 test vector 4 for SHA256", async () => {
    let key = Array.from(Buffer.from("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "hex"));
    let expected = Array.from(Buffer.from("a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5", "hex"));
    let message = Array.from(Buffer.from("Test With Truncation", "utf8"));
    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "hmac",
      template: "HmacSha256",
      params: [message.length, key.length],
    });
    console.log("@Hmac #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ message, key }, { hmac: expected });
  });

  it("should pass RFC 4231 test vector 5 for SHA256", async () => {
    let key = Array.from(Buffer.from("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", "hex"));
    let expected = Array.from(Buffer.from("a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5", "hex"));
    let message = Array.from(Buffer.from("Test With Truncation", "utf8"));
    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "hmac",
      template: "HmacSha256",
      params: [message.length, key.length],
    });
    console.log("@Hmac #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ message, key }, { hmac: expected });
  });

  it("should pass RFC 4231 test vector 6 for SHA256", async () => {
    let key = Array.from(
      Buffer.from(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "hex"
      )
    );
    let message = Array.from(Buffer.from("Test Using Larger Than Block-Size Key - Hash Key First", "utf8"));
    let expected = Array.from(Buffer.from("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "hex"));

    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "hmac",
      template: "HmacSha256",
      params: [message.length, key.length],
    });
    console.log("@Hmac #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ message, key }, { hmac: expected });
  });

  it("should pass RFC 4231 test vector 7 for SHA256", async () => {
    let key = Array.from(
      Buffer.from(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "hex"
      )
    );
    let message = Array.from(
      Buffer.from(
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        "utf8"
      )
    );
    let expected = Array.from(Buffer.from("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", "hex"));

    circuit = await circomkit.WitnessTester(`Cipher`, {
      file: "hmac",
      template: "HmacSha256",
      params: [message.length, key.length],
    });
    console.log("@Hmac #constraints:", await circuit.getConstraintCount());
    await circuit.expectPass({ message, key }, { hmac: expected });
  });
});
