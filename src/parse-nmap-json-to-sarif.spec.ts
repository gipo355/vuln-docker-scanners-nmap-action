import { expect, test, describe } from "vitest";
import fs from "fs";

import {
  convertNmapJsonToSarif,
  readNmapJson,
  writeSarifReport,
} from "./parse-nmap-json-to-sarif";

let json: object | null = null;
let report: object | null = null;

describe("parseNmapJsonToSarif", () => {
  test("should load json file into memory", () => {
    json = readNmapJson("test/assets/vulner-report.json");

    console.log(JSON.stringify(json, null, 2));

    expect(json).toBeDefined();
  });

  test("should convert nmap json to sarif", () => {
    report = convertNmapJsonToSarif(json);

    console.log(JSON.stringify(report, null, 2));

    expect(report).toBeDefined();
  });

  test("should create a sarif file", () => {
    const path = "test/assets/vulner-report.sarif";
    const modifiedPath = writeSarifReport(path, report);

    console.log(modifiedPath);

    const file = fs.readFileSync(modifiedPath, "utf8");

    // expect file to be string
    expect(typeof file).toBe("string");
  });

  // validate sarif with
  // https://sarifweb.azurewebsites.net/Validation
});
