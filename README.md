# Poetry AWS Plugin

This is a poetry plugin to help with AWS CodeArtifact authorization by automatically getting the authorization token.

When installing or publishing packages through poetry and running into a CodeArtifact-related authorization error, the plugin will automatically get the authorization token and retry the command.

The plugin will try two methods of authorization, in this order:

1. Use AWS credentials to run `codeartifact.GetAuthorizationToken`.
2. Use AWS credentials to run `sts.AssumeRole`, then use that role to run `codeartifact.GetAuthorizationToken`.

## Installation

To install the plugin

```
poetry self add poetry-aws-plugin
```

To uninstall the plugin

```
poetry self remove poetry-aws-plugin
```

## Usage

You must ensure that your AWS credentials are configured and discoverable by `boto3`. The [`boto3` documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html#configuring-credentials) has details on how to configure your credentials and the order in which they searched.

When poetry runs a command that uses CodeArtifact and fails to authorize, the plugin will automatically attempt to get the authorization token and retry the command.

Your AWS credentials must be authorized to do atleast one of the following:

1. Run [`codeartifact.GetAuthorizationToken`](https://docs.aws.amazon.com/cli/latest/reference/codeartifact/get-authorization-token.html).
2. Run [`sts.AssumeRole`](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html) to assume a role with authorization to run `codeartifact.GetAuthorizationToken`.

**To use IAM roles to authorize, set the environment variable `POETRY_AWS_PLUGIN_ROLE_ARN` to the role's ARN before running any poetry commands**.

For example:

```bash
export POETRY_AWS_PLUGIN_ROLE_ARN='arn:aws:codeartifact:<region>:<account-id>:repository/<domain>/<domain-owner>/<repository>'
poetry install
```

or

```bash
echo "export POETRY_AWS_PLUGIN_ROLE_ARN='arn:aws:codeartifact:<region>:<account-id>:repository/<domain>/<domain-owner>/<repository>'" >> ~/.bashrc
source ~/.bashrc
poetry install
```

You can find more details in AWS's [CodeArtifact authentication and tokens documentation](https://docs.aws.amazon.com/codeartifact/latest/ug/tokens-authentication.html) and [CodeArtifact IAM documentation](https://docs.aws.amazon.com/codeartifact/latest/ug/security_iam_service-with-iam.html).

# Misc

You can also authorize by setting the environment variable `POETRY_AWS_PLUGIN_AUTH_TOKEN` to the CodeArtifact authorization token. This may be useful in CI/CD pipelines and reduce poetry configuration.
