#!/usr/bin/env python3
import re

src = "all_file_decrypted.txt"
text = open(src, encoding="utf-8").read()

pattern = r"^={40}\nmerged_file:(.*?)\n={40}\n(.*?)(?=\n\n={40}\nmerged_file:|\Z)"

for name, content in re.findall(pattern, text, re.S | re.M):
    with open(name, "w", encoding="utf-8") as f:
        f.write(content.rstrip("\n") + "\n")
    print("还原：", name)


