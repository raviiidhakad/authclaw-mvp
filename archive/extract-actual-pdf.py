from pathlib import Path

from pypdf import PdfReader


pdf_path = Path(r"C:\Users\dhaka\Downloads\AuthClaw_Project_Plan.pdf")
out_path = Path("authclaw_project_plan_actual.txt")

reader = PdfReader(str(pdf_path))
parts = []
for index, page in enumerate(reader.pages, start=1):
    text = page.extract_text() or ""
    parts.append(f"\n\n===== PAGE {index} =====\n\n{text.strip()}")

out_path.write_text("".join(parts).strip(), encoding="utf-8")
print(f"pages={len(reader.pages)}")
print(f"output={out_path.resolve()}")
print(f"chars={out_path.stat().st_size}")
