"""AuthClaw SDK configuration examples."""

from authclaw import (
    ApiKeyConfigurationContract,
    AuthClawClient,
    AuthClawConfig,
    RetryConfigurationContract,
    TimeoutConfigurationContract,
)


def client_from_environment() -> AuthClawClient:
    return AuthClawClient()


def client_from_explicit_configuration() -> AuthClawClient:
    config = AuthClawConfig.from_contracts(
        ApiKeyConfigurationContract(
            api_key="ac_replace_with_your_key",
            base_url="http://localhost:8000",
        ),
        timeout=TimeoutConfigurationContract(
            connect_timeout_seconds=5,
            read_timeout_seconds=30,
        ),
        retry=RetryConfigurationContract(max_attempts=3),
    )
    return AuthClawClient(config=config)


def main() -> None:
    env_client = client_from_environment()
    explicit_client = client_from_explicit_configuration()
    print(env_client.metadata.to_dict())
    print(explicit_client.metadata.to_dict())


if __name__ == "__main__":
    main()
