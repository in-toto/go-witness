# AWS CodeBuild Attestor

This attestor captures AWS CodeBuild metadata and provenance when witness is used within AWS CodeBuild CI/CD pipelines. It collects information about the build, project, source code, and other AWS CodeBuild-specific metadata to provide a verifiable record of the build environment.

## Usage

To use the AWS CodeBuild attestor, include it in your witness invocation:

```bash
witness run \
  --attestor aws-codebuild \
  --attestor git \
  --attestor material \
  --signer <your-signer> \
  --out attestation.json \
  -- <your-build-command>
```

## Environment Variables

The attestor uses the following AWS CodeBuild environment variables:

- `CODEBUILD_BUILD_ID`: The CodeBuild ID for the build
- `CODEBUILD_BUILD_ARN`: The ARN of the build
- `CODEBUILD_BUILD_NUMBER`: The build number
- `CODEBUILD_PROJECT_NAME`: The name of the project being built
- `CODEBUILD_INITIATOR`: The entity that started the build
- `CODEBUILD_RESOLVED_SOURCE_VERSION`: The commit ID for the version of source code being built
- `CODEBUILD_SOURCE_REPO_URL`: The URL to the source code repository
- `CODEBUILD_BATCH_BUILD_IDENTIFIER`: Identifier if part of a batch build
- `CODEBUILD_WEBHOOK_EVENT`: For webhook triggered builds, the webhook event type
- `CODEBUILD_WEBHOOK_HEAD_REF`: For webhook triggered builds, the head reference
- `CODEBUILD_WEBHOOK_ACTOR_ACCOUNT_ID`: For webhook triggered builds, the actor's account ID

## Additional API Data

If AWS credentials and permissions are available, the attestor will also make an API call to fetch additional build details from the AWS CodeBuild API using `BatchGetBuilds`.

## Subjects

The attestor creates the following subjects, which can be used for policy verification and traceability:

- `codebuild-build-id:<build-id>`: The CodeBuild build ID
- `codebuild-project:<project>`: The CodeBuild project name
- `codebuild-source-version:<commit>`: The commit ID of the source code being built