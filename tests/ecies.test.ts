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

    it("Should calculate shared key", async () => {
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
});
