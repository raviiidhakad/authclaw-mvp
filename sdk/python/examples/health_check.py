"""AuthClaw health and version check example."""

from authclaw import AuthClawClient, AuthClawError


def main() -> None:
    client = AuthClawClient()
    try:
        print("health:", client.health())
        print("version:", client.version())
    except AuthClawError as exc:
        print(f"AuthClaw health check failed: {exc}")


if __name__ == "__main__":
    main()
