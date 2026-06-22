import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

app = FastAPI()

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    payload = await request.json()
    is_stream = payload.get("stream", False)

    async def event_generator():
        chunks = [
            '{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-3.5-turbo-0613", "choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}',
            '{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-3.5-turbo-0613", "choices":[{"index":0,"delta":{"content":"My "},"finish_reason":null}]}',
            '{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-3.5-turbo-0613", "choices":[{"index":0,"delta":{"content":"secret "},"finish_reason":null}]}',
            '{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-3.5-turbo-0613", "choices":[{"index":0,"delta":{"content":"password "},"finish_reason":null}]}',
            '{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-3.5-turbo-0613", "choices":[{"index":0,"delta":{"content":"is "},"finish_reason":null}]}',
            '{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-3.5-turbo-0613", "choices":[{"index":0,"delta":{"content":"1234. "},"finish_reason":null}]}',
            '{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-3.5-turbo-0613", "choices":[{"index":0,"delta":{"content":"Do "},"finish_reason":null}]}',
            '{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-3.5-turbo-0613", "choices":[{"index":0,"delta":{"content":"not "},"finish_reason":null}]}',
            '{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-3.5-turbo-0613", "choices":[{"index":0,"delta":{"content":"share."},"finish_reason":null}]}',
            '{"id":"chatcmpl-123","object":"chat.completion.chunk","created":1694268190,"model":"gpt-3.5-turbo-0613", "choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}'
        ]
        
        for chunk in chunks:
            yield f"data: {chunk}\n\n"
            await asyncio.sleep(0.1)  # Simulate network latency
            
        yield "data: [DONE]\n\n"

    if is_stream:
        return StreamingResponse(event_generator(), media_type="text/event-stream")
    else:
        return {"choices": [{"message": {"role": "assistant", "content": "My secret password is 1234. Do not share."}}], "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
