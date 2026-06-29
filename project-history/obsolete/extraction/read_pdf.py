import fitz

def main():
    doc = fitz.open(r"C:\Users\dhaka\.gemini\antigravity\brain\8be91cef-0fab-4ec0-baaf-660ebaf94212\media__1781601697516.pdf")
    text = '\n'.join([page.get_text() for page in doc])
    with open(r"pdf_content.txt", "w", encoding="utf-8") as f:
        f.write(text)

if __name__ == "__main__":
    main()
