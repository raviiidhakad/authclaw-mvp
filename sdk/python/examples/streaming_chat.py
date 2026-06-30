"""AuthClaw streaming chat completion example."""

from authclaw import AuthClawClient, AuthClawError, ChatMessage, MessageRole, StreamingRequestContract


def main() -> None:
    client = AuthClawClient()
    request = StreamingRequestContract(
        model="llama-3.3-70b-versatile",
        messages=(ChatMessage(role=MessageRole.USER, content="Stream three security tips."),),
    )

    try:
        with client.stream_chat_completion(request) as stream:
            for event in stream:
                print(event.content, end="", flush=True)
    except AuthClawError as exc:
        print(f"\nAuthClaw stream failed: {exc}")


if __name__ == "__main__":
    main()
