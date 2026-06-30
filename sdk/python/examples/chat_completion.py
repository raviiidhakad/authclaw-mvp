"""Basic AuthClaw chat completion example."""

from authclaw import AuthClawClient, AuthClawError, ChatCompletionRequestContract, ChatMessage, MessageRole


def main() -> None:
    client = AuthClawClient()
    request = ChatCompletionRequestContract(
        model="llama-3.3-70b-versatile",
        messages=(ChatMessage(role=MessageRole.USER, content="Explain zero trust in one paragraph."),),
    )

    try:
        response = client.create_chat_completion(request)
    except AuthClawError as exc:
        print(f"AuthClaw request failed: {exc}")
        return

    print(response.choices[0].message.content)


if __name__ == "__main__":
    main()
