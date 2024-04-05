import os
import re
from typing import Any

import boto3
import requests

from botocore.exceptions import ClientError
from cleo.io.io import IO, Verbosity
from poetry.exceptions import PoetryException
from poetry.plugins import Plugin
from poetry.poetry import Poetry
from poetry.utils.authenticator import Authenticator
from poetry.utils.password_manager import HTTPAuthCredential

POETRY_AWS_PLUGIN_ROLE_ARN_VAR = "POETRY_AWS_PLUGIN_ROLE_ARN"
POETRY_AWS_PLUGIN_SESSION_NAME = "poetry-aws-plugin"
POETRY_AWS_PLUGIN_AUTH_TOKEN_VAR = "POETRY_AWS_PLUGIN_AUTH_TOKEN"

UNAUTHORIZED_STATUS_CODES = (401, 403)
CODEARTIFACT_URL_REGEX = r"^https://([a-z][a-z-]*)-(\d+)\.d\.codeartifact\.[^.]+\.amazonaws\.com/.*$"

RETRY_ERROR_MESSAGE = f"""\
Make sure you have AWS credentials configured and up-to-date

Then make sure you have atleast one of the following:
    1. Authorization for CodeArtifact with your current credentials
    2. Authorization for an IAM role that has access to CodeArtifact and
       environment variable '{POETRY_AWS_PLUGIN_ROLE_ARN_VAR}' set to that role's ARN

"""


def patch(io: IO):
    request = Authenticator.request

    def is_retryable(response: requests.Response) -> bool:
        if response.status_code not in UNAUTHORIZED_STATUS_CODES:
            return False
        if not re.match(CODEARTIFACT_URL_REGEX, response.url):
            return False
        return True

    def validate_credentials() -> bool:
        try:
            boto3.client("sts").get_caller_identity()
            return True
        except ClientError as err:
            io.write_line(f"\nError using current credentials: {err}\n")
            return False
        except Exception as err:
            io.write_line("Unexpected error while validating AWS credentials\n")
            io.write_line(RETRY_ERROR_MESSAGE)
            raise err

    def get_auth_token_with_current_credentials(domain: str, domain_owner: str) -> str:
        try:
            token_response = boto3.client("codeartifact").get_authorization_token(
                domain=domain,
                domainOwner=domain_owner,
            )
            return token_response["authorizationToken"]
        except ClientError as err:
            io.write_line(
                f"\nError getting CodeArtifact token using current credentials: {err}\n",
                verbosity=Verbosity.VERBOSE,
            )
            return ""
        except Exception as err:
            io.write_line("Unexpected error while getting CodeArtifact authorization token\n")
            io.write_line(RETRY_ERROR_MESSAGE)
            raise err

    def get_auth_token_with_iam_role(domain: str, domain_owner: str) -> str:
        role_arn = os.environ.get(POETRY_AWS_PLUGIN_ROLE_ARN_VAR)
        if not role_arn:
            io.write_line(
                f"\nError getting CodeArtifact token using IAM role: "
                f"Environment variable '{POETRY_AWS_PLUGIN_ROLE_ARN_VAR}' not found\n",
                verbosity=Verbosity.VERBOSE,
            )
            return ""

        try:
            assume_role_response = boto3.client("sts").assume_role(
                RoleArn=role_arn,
                RoleSessionName=POETRY_AWS_PLUGIN_SESSION_NAME,
            )
            credentials = assume_role_response["Credentials"]
            session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
            )

            token_response = session.client("codeartifact").get_authorization_token(
                domain=domain,
                domainOwner=domain_owner,
            )
            return token_response["authorizationToken"]
        except ClientError as err:
            io.write_line(
                f"\nError getting CodeArtifact token using IAM role '{role_arn}': {err}\n",
                verbosity=Verbosity.VERBOSE,
            )
            return ""
        except Exception as err:
            io.write_line(
                "Unexpected error while assuming CodeArtifact role and getting CodeArtifact authorization token\n"
            )
            io.write_line(RETRY_ERROR_MESSAGE)
            raise err

    def get_auth_token_from_env(*args: Any, **kwargs: Any) -> str:
        return os.environ.get(POETRY_AWS_PLUGIN_AUTH_TOKEN_VAR, "")

    def get_auth_token(domain: str, domain_owner: str) -> str:
        io.write_line(
            "\nGetting new CodeArtifact authorization token for "
            f"domain '{domain}' and domain owner '{domain_owner}'\n",
            verbosity=Verbosity.VERBOSE,
        )

        is_valid = validate_credentials()
        if not is_valid:
            return ""

        # We'll try these methods to get the CodeArtifact token
        methods = [
            get_auth_token_with_current_credentials,
            get_auth_token_with_iam_role,
            get_auth_token_from_env,
        ]
        for method in methods:
            auth_token = method(domain, domain_owner)
            if auth_token:
                return auth_token

        return ""

    def patched_request(
        self: Authenticator,
        method: str,
        url: str,
        raise_for_status: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        response = request(self, method=method, url=url, raise_for_status=False, **kwargs)

        if is_retryable(response):
            io.write_line(
                "\nFailed to get authorization for CodeArtifact\n",
                verbosity=Verbosity.VERBOSE,
            )

            match = re.match(CODEARTIFACT_URL_REGEX, response.url)
            domain, domain_owner = match.groups()

            auth_token = get_auth_token(domain, domain_owner)
            if not auth_token:
                raise PoetryException(RETRY_ERROR_MESSAGE)

            io.write_line(
                "\nSuccessfully got CodeArtifact authorization token!\n\nRetrying request...\n",
                verbosity=Verbosity.VERBOSE,
            )

            # Overwrite the credentials for this URL
            self._credentials[url] = HTTPAuthCredential(username="aws", password=auth_token)

            # Now retry the original request with new credentials
            return request(self, method=method, url=url, raise_for_status=raise_for_status, **kwargs)

        if raise_for_status:
            response.raise_for_status()
        return response

    Authenticator.request = patched_request


class PoetryAwsPlugin(Plugin):
    def activate(self, _: Poetry, io: IO) -> None:
        patch(io)
