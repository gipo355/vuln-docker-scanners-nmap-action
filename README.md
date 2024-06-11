# Github Action for running nmap on the target

Uses cli tool from docker container <https://github.com/gipo355/vuln-docker-scanners>

using <https://github.com/actions/toolkit> with octokit

TODO:
add create issue input, issue name

NOTE:

## Permissions

requires `security-events` and `issues` write

## Inputs

### `github_token`

**Required** The github token to use for the action in order to create an issue.

### `target`

**Required** The target to scan. Default `localhost`.

### `port`

The port to scan. Default all ports.

- `-p-` for all ports
- `-p90,443` for specific ports

### `generate-reports`

Generate reports in the `reports` folder. Default `false`.

outputs $name/$type/$name.[xml|nmap|gnmap|sarif|json]

### `generate-sarif`

Generate sarif in the `reports` folder. Default `false`.

### `output-dir`

The directory to output the reports. Default `nmap-reports`, relative to `$WORKDIR`.

### `nmap-flags`

Additional flags to pass to nmap. Default ``.

Example: `-sP`

If provided, will execute direct scan

### `vulner`

Execute vulner script. Default `false`.

### `vulscan`

Execute vulscan script. Default `false`.
