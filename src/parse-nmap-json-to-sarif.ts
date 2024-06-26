// @ts-nocheck
import fs from "node:fs";

export const createNmapSarifFromJson = (path: string): string => {
  const json = readNmapJson(path);

  const report = convertNmapJsonToSarif(json);

  const newFilePath = writeSarifReport(path, report);

  return newFilePath;
};

export function convertNmapJsonToSarif(json: any): any {
  // Read the Vulners report
  // let vulnersReport = JSON.parse(
  //   fs.readFileSync(
  //     "/home/wolf/Programming/CURRENT/vuln-docker-scanners-nmap-action/test/assets/vulners-report.json",
  //     "utf8",
  //   ),
  // );
  let vulnersReport = json;

  // Initialize the SARIF report
  let sarifReport = {
    $schema:
      "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Vulner Scanner",
            version: vulnersReport["Version"],
            informationUri: "https://vulners.com",
            rules: [],
          },
        },
        results: [],
      },
    ],
  };

  // Convert each vulnerability to a SARIF result
  for (let host of vulnersReport["Host"]) {
    for (let port of host["Port"]) {
      // check if script is iterable
      if (!port["Script"].length) {
        for (let script of port["Script"]) {
          if (script["ID"] === "vulners") {
            let cves = script["Output"]
              .split("\n")
              .filter((line) => line.startsWith("    \t"))
              .map((line) => line.split("\t")[1]);

            for (let cve of cves) {
              // Add the rule for this vulnerability
              sarifReport["runs"][0]["tool"]["driver"]["rules"].push({
                id: cve,
                name: cve,
                shortDescription: {
                  text: cve,
                },
                helpUri: `https://vulners.com/cve/${cve}`,
                properties: {
                  cwe: cve,
                },
              });

              // Add the result for this vulnerability
              sarifReport["runs"][0]["results"].push({
                ruleId: cve,
                level: "note",
                message: {
                  text: `tcp://${host["HostAddress"][0]["Address"]}:${port["PortID"]}`,
                },
                locations: [
                  {
                    physicalLocation: {
                      address: {
                        absoluteAddress: -1,
                      },
                    },
                  },
                ],
              });
            } // for cve of cves
          } // if script["ID"] === "vulners"
        } // script of port["Script"]
      } else {
        // if port["Script"].length
        const script = port["Script"];

        if (script["ID"] === "vulners") {
          let cves = script["Output"]
            .split("\n")
            .filter((line) => line.startsWith("    \t"))
            .map((line) => line.split("\t")[1]);

          for (let cve of cves) {
            // Add the rule for this vulnerability
            sarifReport["runs"][0]["tool"]["driver"]["rules"].push({
              id: cve,
              name: cve,
              shortDescription: {
                text: cve,
              },
              helpUri: `https://vulners.com/cve/${cve}`,
              properties: {
                cwe: cve,
              },
            });

            // Add the result for this vulnerability
            sarifReport["runs"][0]["results"].push({
              ruleId: cve,
              level: "note",
              message: {
                text: `tcp://${host["HostAddress"][0]["Address"]}:${port["PortID"]}`,
              },
              locations: [
                {
                  physicalLocation: {
                    address: {
                      absoluteAddress: -1,
                    },
                  },
                },
              ],
            });
          } // for cve of cves
        } // if script["ID"] === "vulners"
      }
    } //  port of host["Port"]
  } // host of vulnersReport["Host"]

  return sarifReport;
}

export function readNmapJson(path: string): any {
  const file = fs.readFileSync(path, "utf8");

  return JSON.parse(file);
}

export function writeSarifReport(path: string, report: any): string {
  const modifiedPath = path.replace(".json", ".sarif");

  fs.writeFileSync(modifiedPath, JSON.stringify(report, null, 2));

  return modifiedPath;
}
