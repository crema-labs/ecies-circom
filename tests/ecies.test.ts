import { WitnessTester } from "circomkit";
import { circomkit, bigint_to_array } from "./common";
import { Point } from "@noble/secp256k1";

describe("ECIES", () => {
  describe("GenSharedKey", () => {
    let circuit: WitnessTester<["r", "px", "py"], ["out"]>;
    before(async () => {
      circuit = await circomkit.WitnessTester(`GenSharedKey`, {
        file: "encrypt",
        template: "GenSharedKey",
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    let r1_big = BigInt("0x7ebbc6a8358bc76dd73ebc557056702c8cfc34e5cfcd90eb83af0347575fd2ad");

    let p2 = Point.fromPrivateKey(
      Buffer.from("6a3d6396903245bba5837752b9e0348874e72db0c4e11e9c485a81b4ea4353b9", "hex")
    );

    let p3 = p2.multiply(r1_big);

    it("should calculate shared key", async () => {
      await circuit.expectPass(
        {
          r: bigint_to_array(64, 4, r1_big),
          px: bigint_to_array(64, 4, p2.x),
          py: bigint_to_array(64, 4, p2.y),
        },
        { out: bigint_to_array(8, 32, p3.x).reverse() }
      );
    });
  });
  describe("Encrypt", () => {
    let circuit: WitnessTester<["r", "x", "y", "pt", "iv", "s1", "s2"], ["pubkey", "ct", "hmac"]>;
    before(async () => {
      circuit = await circomkit.WitnessTester(`Encrypt`, {
        file: "encrypt",
        template: "Encrypt",
        params: [13, 0, 0],
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    let r_big = BigInt("0xfc1ee2898c6f0ae4aa5782fc0775377b672dac1e0d51190bffb02e9a274e7b58");
    let r_pubkey = Point.fromPrivateKey(
      Buffer.from("fc1ee2898c6f0ae4aa5782fc0775377b672dac1e0d51190bffb02e9a274e7b58", "hex")
    );

    let pubkey = Point.fromPrivateKey(
      Buffer.from("83b44f7f1a20fd3a4020f021fc0ceb18f1ee5ebfb36d7eedabb8ea732292ab07", "hex")
    );

    let pt = Buffer.from("48656c6c6f2c20776f726c642e", "hex");
    let iv = Buffer.from("69c7d4f59222328e23ebc96549ffc387", "hex");
    let ct = Buffer.from("474083d5548777ba10617bb3fe", "hex");
    let hmac = Buffer.from("6ec1fbf640897afee67e2bc9e49b9a8ed548d3396b428a238f515a0c1e5f0719", "hex");

    it("should encrypt", async () => {
      await circuit.expectPass(
        {
          r: bigint_to_array(8, 32, r_big),
          x: bigint_to_array(8, 32, pubkey.x),
          y: bigint_to_array(8, 32, pubkey.y),
          pt: Array.from(pt),
          iv: Array.from(iv),
          s1: [],
          s2: [],
        },
        {
          ct: Array.from(ct),
          hmac: Array.from(hmac),
          pubkey: [bigint_to_array(64, 4, r_pubkey.x), bigint_to_array(64, 4, r_pubkey.y)],
        }
      );
    });
  });
  describe("KeyGen", () => {
    let circuit: WitnessTester<["info", "key"], ["out"]>;
    before(async () => {
      circuit = await circomkit.WitnessTester(`KeyGen`, {
        file: "encrypt",
        template: "KeyGen",
        params: [0],
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    let key = Buffer.from("4afadb36a761b836911355462e37ad392542f1a6ab6926ed69b1b97495c5cb32", "hex");
    let k1 = Buffer.from("978a6083d0566d877fe6663fa8451182", "hex");
    let k2 = Buffer.from("7035b86855fdfdcf410db36e9e5cf014", "hex");

    it("should encrpyt", async () => {
      await circuit.expectPass(
        {
          key: Array.from(key),
          info: [],
        },
        {
          out: [Array.from(k1), Array.from(k2)],
        }
      );
    });
  });
});
