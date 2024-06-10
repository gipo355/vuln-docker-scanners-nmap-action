import { expect, test, describe } from "vitest";

import {
  convertNmapJsonToSarif,
  readNmapJson,
} from "./parse-nmap-json-to-sarif";

let json: object | null = null;

describe("parseNmapJsonToSarif", () => {
  test("should load json file into memory", () => {
    json = readNmapJson("test/assets/vulners-report.json");

    console.log(JSON.stringify(json, null, 2));

    expect(json).toBeDefined();
  });

  test("should convert nmap json to sarif", () => {
    const report = convertNmapJsonToSarif(json);

    console.log(JSON.stringify(report, null, 2));

    expect(report).toBeDefined();
  });
});
