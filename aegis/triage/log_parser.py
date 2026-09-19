import os
import re

P = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s*\|\s*IP=(?P<ip>[^|]+)\s*\|\s*"
    r"USER=(?P<user>[^|]+)\s*\|\s*CMD=(?P<cmd>.*)$"
)

def parse_logs(filepath: str) -> list[dict[str, str]]:
    out = []
    if not os.path.exists(filepath):
        return out
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            match = P.match(line.strip())
            if match:
                out.append({key: value.strip() for key, value in match.groupdict().items()})
    return out
