# Generating Test SBOM

## Commands Used

These are the commands used to generate the SBOMs comitted:

`syft scan alpine:latest -o spdx > spdx-2.3/alpine.spdx-2-3.json`

`syft scan alpine:latest -o spdx-json@2.2 > spdx-2.2/alpine.spdx-2-2.json`

`syft scan alpine:latest -o cyclonedx-json > cyclonedx-json/alpine.cyclonedx.json`

`syft scan alpine:latest -o cyclonedx > alpine.cyclonedx.xml`

For the `bad.json` modified any of the above json SBOMs to be malformed (just remove a few characters from the end). The modification needs to be after the first 512 bytes of the file due to the method used for mime-type detection.
