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

    it("should add two numbers", async () => {
      await circuit.expectPass(
        {
          r: [9132111095178970989, 15510041241853521964, 10159053021079507179, 9488806544836383405], // 7ebbc6a8358bc76dd73ebc557056702c8cfc34e5cfcd90eb83af0347575fd2ad
          px: [9506501716761942116, 10549001985784506235, 1496101770422782058, 637345402428733412], // 83ede0f19c3c98649265956a4193677b14c338a22de2086a08d84e4446fe37e4
          py: [16299450101563953371, 17218720768490803084, 4063951964664995139, 11207890590534320165], // e233478259ec90dbeef52f4f6c890f8c38660ec7b61b9d439b8a6d1c323dc025
        },
        { out: Array.from(Buffer.from("1167ccc13ac5e8a26b131c3446030c60fbfac6aa8e31149d0869f93626a4cdf62234", "hex")) }
      );
    });
  });
});
