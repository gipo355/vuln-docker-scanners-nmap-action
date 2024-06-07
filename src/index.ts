import {
  setFailed,
  // ExitCode
} from "@actions/core";
import { exec } from "@actions/exec";
import fs from "node:fs";
import { getOctokit, context } from "@actions/github";
import { inputs } from "./inputs";
import { collapsibleWrapper } from "./utils";

async function main() {
  const workspace = process.env.GITHUB_WORKSPACE;
  const currentRunnerID = context.runId;

  if (!workspace) {
    throw new Error("GITHUB_WORKSPACE is not defined");
  }

  const repoName = context.repo.repo;
  const repoOwner = context.repo.owner;

  const imageName = "gipo355/vuln-docker-scanners:latest";

  console.log(
    `🚀 Starting the action! workspace: ${workspace} currentRunnerID: ${currentRunnerID} `,
  );

  console.log(`Pulling the image: ${imageName}`);
  let pullCmd = `docker pull ${imageName} -q`;
  await exec(pullCmd);

  const runCmd = [
    "docker",
    "run",
    "--workdir=/app",
    `-v ${workspace}:/app`,
    `--network=host`,
    `${imageName}`,
    "nmap",
    "--target=" + inputs.target,
    inputs.outputDir && "--output-dir=" + inputs.outputDir,
    inputs.wantVulscan && "--vulscan=true",
    inputs.wantWulners && "--vulner=true",
    inputs.wantReports && `--generate-reports=true`,
    inputs.nmapFlags && `--args="${inputs.nmapFlags}"`,
  ].join(" ");

  console.log(`🚀 Executing attack: ${runCmd}`);
  await exec(runCmd);

  inputs.outputDir ??= "nmap-reports";

  const body = [];

  // Get the reports and parse json to sarif
  const vulnerPath = `${workspace}/${inputs.outputDir}/vulners/vulners-report.json`;
  const vulscanPath = `${workspace}/${inputs.outputDir}/vulscan/vulscan-report.json`;
  const directPath = `${workspace}/${inputs.outputDir}/direct/direct-report.json`;

  // TODO: optimize this, some files can reach 50mb
  if (inputs.wantReports) {
    if (inputs.wantVulscan) {
      const vulscanContent = await fs.promises.readFile(vulscanPath);

      body.push(
        collapsibleWrapper("Vulscan Report", vulscanContent.toString()),
      );
    }

    if (inputs.wantWulners) {
      const vulnerContent = await fs.promises.readFile(vulnerPath);
      body.push(collapsibleWrapper("Vulners Report", vulnerContent.toString()));
    }

    if (inputs.nmapFlags) {
      const directContent = await fs.promises.readFile(directPath);
      body.push(collapsibleWrapper("Direct Report", directContent.toString()));
    }
  }

  const octokit = getOctokit(inputs.githubToken);

  // TODO: put in inputs to allow creating issues. we are testing for now
  // Ideally we want to create a sarif and upload to code scans
  // create an issue with the reports
  // IF CREATEISSUE
  await octokit.rest.issues.create({
    owner: repoOwner,
    repo: repoName,
    title: "Vulnerability reports from Nmap scan",
    body: body.join("\n"),
  });

  // IF GENERATESARIF
}

main().catch((error) => {
  console.error(error);
  setFailed("Action failed");
});
