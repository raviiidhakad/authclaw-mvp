import fs from "node:fs";

const htmlPath = process.argv[2] ?? "chatgpt-share.html";
const html = fs.readFileSync(htmlPath, "utf8");

const payloads = [];
const enqueuePattern = /streamController\.enqueue\(("(?:\\.|[^\\"])*")\)/g;
let match;
while ((match = enqueuePattern.exec(html))) {
  const payload = JSON.parse(match[1]);
  if (payload.startsWith("[")) payloads.push(payload);
}

if (!payloads.length) {
  throw new Error("No JSON payload found in shared chat HTML.");
}

const encoded = JSON.parse(payloads[0]);

const decode = (value, seen = new Map()) => {
  if (typeof value === "number") {
    if (value < 0) return null;
    return decode(encoded[value], seen);
  }

  if (typeof value !== "object" || value === null) return value;
  if (seen.has(value)) return seen.get(value);

  if (Array.isArray(value)) {
    const out = [];
    seen.set(value, out);
    for (const item of value) out.push(decode(item, seen));
    return out;
  }

  const out = {};
  seen.set(value, out);
  for (const [rawKey, rawValue] of Object.entries(value)) {
    const keyIndex = /^_(\d+)$/.exec(rawKey)?.[1];
    const key = keyIndex ? decode(Number(keyIndex), seen) : rawKey;
    out[key] = decode(rawValue, seen);
  }
  return out;
};

const decoded = decode(0);
const route = decoded?.loaderData?.["routes/share.$shareId.($action)"];
const data = route?.serverResponse?.data ?? route?.serverResponse ?? decoded;

const messages = [];
const linear = data.linear_conversation ?? [];
for (const item of linear) {
  const message = item?.message ?? item;
  const role = message?.author?.role;
  const parts = message?.content?.parts;
  if (!role || !Array.isArray(parts)) continue;
  const text = parts
    .map((part) => {
      if (typeof part === "string") return part;
      if (part?.text) return part.text;
      if (part?.content) return part.content;
      return "";
    })
    .join("\n")
    .trim();
  if (text) messages.push({ role, text });
}

const transcript = messages
  .map((message, index) => `## ${index + 1}. ${message.role.toUpperCase()}\n\n${message.text}`)
  .join("\n\n---\n\n");

fs.writeFileSync("chatgpt-share-transcript.md", transcript);

const circularSafe = () => {
  const seen = new WeakSet();
  return (_key, value) => {
    if (typeof value !== "object" || value === null) return value;
    if (seen.has(value)) return "[Circular]";
    seen.add(value);
    return value;
  };
};

fs.writeFileSync("chatgpt-share-decoded.json", JSON.stringify(decoded, circularSafe(), 2));

console.log(JSON.stringify({
  title: data.title,
  create_time: data.create_time,
  update_time: data.update_time,
  message_count: messages.length,
  transcript_path: "chatgpt-share-transcript.md",
  decoded_path: "chatgpt-share-decoded.json"
}, null, 2));
