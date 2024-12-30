import { WitnessTester } from "circomkit";
import { circomkit } from "./common";

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

    it("Should calculate shared key", async () => {
      await circuit.expectPass(
        {
          r: [0x7ebbc6a8358bc76d, 0xd73ebc557056702c, 0x8cfc34e5cfcd90eb, 0x83af0347575fd2ad], // 7ebbc6a8358bc76dd73ebc557056702c8cfc34e5cfcd90eb83af0347575fd2ad
          px: [0x83ede0f19c3c9864, 0x9265956a4193677b, 0x14c338a22de2086a, 0x08d84e4446fe37e4], // 83ede0f19c3c98649265956a4193677b14c338a22de2086a08d84e4446fe37e4
          py: [0xe233478259ec90db, 0xeef52f4f6c890f8c, 0x38660ec7b61b9d43, 0x9b8a6d1c323dc025], // e233478259ec90dbeef52f4f6c890f8c38660ec7b61b9d439b8a6d1c323dc025
        },
        { out: Array.from(Buffer.from("1167ccc13ac5e8a26b131c3446030c60fbfac6aa8e31149d0869f93626a4cdf62234", "hex")) }
      );
    });
  });
});
