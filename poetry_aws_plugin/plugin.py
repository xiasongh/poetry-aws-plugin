import logging
import os
import re
from typing import Any

import boto3
import requests
from requests.utils import rewind_body

from botocore.exceptions import ClientError
from poetry.exceptions import PoetryException
from poetry.plugins import Plugin
from poetry.publishing.uploader import Uploader
from poetry.utils.authenticator import Authenticator

POETRY_AWS_PLUGIN_ROLE_ARN_VAR = "POETRY_AWS_PLUGIN_ROLE_ARN"
POETRY_AWS_PLUGIN_SESSION_NAME = "poetry-aws-plugin"
POETRY_AWS_PLUGIN_AUTH_TOKEN_VAR = "POETRY_AWS_PLUGIN_AUTH_TOKEN"

UNAUTHORIZED_STATUS_CODES = (401, 403)
CODEARTIFACT_URL_REGEX = r"^https://([a-z][a-z-]*)-(\d+)\.d\.codeartifact\.[^.]+\.amazonaws\.com.*$"

RETRY_ERROR_MESSAGE = f"""
Make sure you have AWS credentials configured and up-to-date

Then make sure you have atleast one of the following:
    1. Authorization for CodeArtifact with your current credentials
    2. Authorization for an IAM role that has access to CodeArtifact and
       environment variable '{POETRY_AWS_PLUGIN_ROLE_ARN_VAR}' set to that role's ARN
"""

logger = logging.getLogger("PoetryAwsPlugin")


authenticator_create_session = Authenticator.create_session
uploader_make_session = Uploader.make_session


def is_retryable(response: requests.Response) -> bool:
    if response.status_code not in UNAUTHORIZED_STATUS_CODES:
        return False
    if not re.match(CODEARTIFACT_URL_REGEX, response.url):
        return False
    return True


def get_auth_token(domain: str, domain_owner: str) -> str:
    logger.debug(
        f"Getting new CodeArtifact authorization token for domain '{domain}' and domain owner '{domain_owner}'"
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


def validate_credentials() -> bool:
    try:
        boto3.client("sts").get_caller_identity()
        return True
    except ClientError as err:
        logger.debug(f"Error using current credentials: {err}")
        return False
    except Exception as err:
        logger.debug(f"Unexpected error while validating AWS credentials\n{RETRY_ERROR_MESSAGE}")
        raise err


def get_auth_token_with_current_credentials(domain: str, domain_owner: str) -> str:
    try:
        token_response = boto3.client("codeartifact").get_authorization_token(
            domain=domain,
            domainOwner=domain_owner,
        )
        return token_response["authorizationToken"]
    except ClientError as err:
        logger.debug(f"Error getting CodeArtifact token using current credentials: {err}")
    except Exception as err:
        logger.debug(f"Unexpected error while getting CodeArtifact authorization token: {err}")
    return ""


def get_auth_token_with_iam_role(domain: str, domain_owner: str) -> str:
    role_arn = os.environ.get(POETRY_AWS_PLUGIN_ROLE_ARN_VAR)
    if not role_arn:
        logger.debug(
            f"Error getting CodeArtifact token using IAM role: "
            f"Environment variable '{POETRY_AWS_PLUGIN_ROLE_ARN_VAR}' not found"
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
        logger.debug(f"Error getting CodeArtifact token using IAM role '{role_arn}': {err}")
    except Exception as err:
        logger.debug(
            f"Unexpected error while assuming CodeArtifact role and getting CodeArtifact authorization token: {err}"
        )
    return ""


def get_auth_token_from_env(*args: Any, **kwargs: Any) -> str:
    return os.environ.get(POETRY_AWS_PLUGIN_AUTH_TOKEN_VAR, "")


def patched_session_send(self: requests.Session, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
    response = requests.Session.send(self, request.copy(), **kwargs.copy())
    if not is_retryable(response):
        return response

    logger.debug("Failed to get authorization for CodeArtifact")

    match = re.match(CODEARTIFACT_URL_REGEX, response.url)
    domain, domain_owner = match.groups()

    auth_token = get_auth_token(domain, domain_owner)
    if not auth_token:
        raise PoetryException(RETRY_ERROR_MESSAGE)

    logger.debug("Successfully got CodeArtifact authorization token\nRetrying request")

    # Use the received auth token for the session
    self.auth = ("aws", auth_token)

    # And create a new request using the new auth
    new_request = request.copy()
    rewind_body(new_request)
    new_request.prepare_auth(self.auth, request.url)

    # And finally we retry the request
    return requests.Session.send(self, new_request, **kwargs)


def patched_authenticator_create_session(self: Authenticator) -> requests.Session:
    session = authenticator_create_session(self)
    session.send = patched_session_send.__get__(session)
    return session


def patched_uploader_make_session(self: Uploader) -> requests.Session:
    session = uploader_make_session(self)
    session.send = patched_session_send.__get__(session)
    return session


class PoetryAwsPlugin(Plugin):
    def activate(self, *args: Any, **kwargs: Any) -> None:
        Authenticator.create_session = patched_authenticator_create_session
        Uploader.make_session = patched_uploader_make_session