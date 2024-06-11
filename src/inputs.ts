import { getInput } from "@actions/core";

export const inputs = {
  githubToken: getInput("github_token"),
  port: getInput("port"),
  target: getInput("target"),
  wantVulner: getInput("vulner"),
  wantVulscan: getInput("vulscan"),
  wantReports: getInput("generate_reports"),
  outputDir: getInput("output_dir"),
  wantSarif: getInput("generate_sarif"),
  nmapFlags: getInput("flags"),
};
