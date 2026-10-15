#!/usr/bin/env python3
"""Exit 0 when a comment only says thanks or confirms a fix, 1 otherwise.

Used by reopen-on-comment.yml so "works now, thanks!" on a closed issue
doesn't reopen it. Anything longer than a short note, with a question, an
image or a sign of trouble counts as a follow-up.
"""
import re
import sys

THANKS = re.compile(
    r"\b(thanks?|thank\s*you|thx|ty|cheers|appreciated?|works?|worked|working|"
    r"fixed|solved|resolved|perfect|awesome|great|brilliant|excellent|confirmed?)\b"
    r"|👍|🙏|🎉|❤️",
    re.I,
)
TROUBLE = re.compile(
    r"\?|\b(but|still|not|no|doesn'?t|don'?t|didn'?t|isn'?t|won'?t|can'?t|cannot|"
    r"fail\w*|error\w*|issue|problem|bug|broke\w*|again|however|except|unless|"
    r"also|another|same|too|please|pls|how|what|why|when|where|which|could|would|"
    r"is there|are there|can (?:you|i|we))\b",
    re.I,
)


def strip_reply(body: str) -> str:
    """Drop quoted text and the tail of an email reply."""
    lines = []
    for line in body.splitlines():
        s = line.strip()
        if re.match(r"^(_{8,}|-{2,}\s*Original Message|From:\s|On .+ wrote:$)", s):
            break
        if s.startswith(">"):
            continue
        lines.append(s)
    return " ".join(l for l in lines if l).strip()


def is_thanks(body: str) -> bool:
    text = strip_reply(body)
    if re.search(r"!\[|<img|```|https?://", text):
        return False
    return 0 < len(text) <= 200 and bool(THANKS.search(text)) and not TROUBLE.search(text)


if __name__ == "__main__":
    sys.exit(0 if is_thanks(sys.stdin.read()) else 1)
