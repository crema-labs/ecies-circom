import { WitnessTester } from "circomkit";
import { circomkit, bigint_to_array } from "./common";

describe("Utils", () => {
  describe("StridesToBytes", () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    before(async () => {
      circuit = await circomkit.WitnessTester(`StridesToBytes`, {
        file: "utils",
        template: "StridesToBytes",
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    let r1_big = BigInt("0x7ebbc6a8358bc76dd73ebc557056702c8cfc34e5cfcd90eb83af0347575fd2ad");
    it("should convert 64bit strides to 8bit strides", async () => {
      await circuit.expectPass(
        {
          in: bigint_to_array(64, 4, r1_big),
        },
        { out: bigint_to_array(8, 32, r1_big) }
      );
    });
  });
  describe("BytesToStrides", () => {
    let circuit: WitnessTester<["in"], ["out"]>;
    before(async () => {
      circuit = await circomkit.WitnessTester(`BytesToStrides`, {
        file: "utils",
        template: "BytesToStrides",
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    let r1_big = BigInt("0x7ebbc6a8358bc76dd73ebc557056702c8cfc34e5cfcd90eb83af0347575fd2ad");
    it("should convert 8bit strides to 64bit strides", async () => {
      await circuit.expectPass(
        {
          in: bigint_to_array(8, 32, r1_big),
        },
        { out: bigint_to_array(64, 4, r1_big) }
      );
    });
  });
});
