# dev moving to

vuln-docker-scanners for the cli

vuln-docker-scanners-$tool-action for the github action

# Hello world docker action with go

This action prints "Hello World" or "Hello" + the name of a person to greet to the log.

## Inputs

## `who-to-greet`

**Required** The name of the person to greet. Default `"World"`.

## Outputs

## `time`

The time we greeted you.

## Example usage

uses: actions/hello-world-docker-action@v1
with:
who-to-greet: 'Mona the Octocat'

## note for nmap

we are using a docker container which allows us to pull and prepare needed tools for the scan.

if we were to use a js action, we would have to install nmap on the runner machine which is not ideal.

golang provides efficient concurrency and minimal image + mem size for containers using alpine.

# todo

- add licenses
- fork vulner repo
- copy vulner scripts in continer
- add more nmap options
- create auto release and docker publish on tag
- generate sarif report
- add cobra and viper
- split github utils in its own lib
- understand golang versioning forlib
- split smiattack cli with nmap in its own repo for action using the github lib and utils

- make a list of all go libs and tools

# splits

action repo

- uses docker wrapper repo
- uses github utils repo to get input

cli nmap repo

- provides commands like scan, list, etc
- provides writeToFile, writeToSarif, output to console

utils repo

- provides github utils like getRepo, getIssue, etc

# libs

nmap formatter already available
<https://github.com/vdjagilev/nmap-formatter/wiki/Use-as-a-library>
<https://github.com/vdjagilev/nmap-formatter>

<https://gist.github.com/PSJoshi/1ddb53b42a1b099355df9eac86ced222>

# CREDITS

thank you @vdjagilev for the nmap formatter lib

# note

requires `--network=host` to run nmap in docker

also needs a volume mounted to $workdir to extract reports

set workdir with `--workdir` flag

_note we don't set workdir by default to provide compatibility with github actions_

by default it will emit them in $workdir/$report-dir/$report-name/$report-name.ext

changing the workdir will change the location of the reports

example:

we encapsulate the nmap command to be able to extend this cli with more programs later on

`docker run --network=host --workdir=/app --volume .:/app gipo355/vuln-docker-scanners nmap --vulner --vulscan --target=localhost --port=80 --generate-reports --generate-sarif`
