#!/usr/bin/env python3
"""
Minimal polymorphic build preprocessor for hidemylogs.

Modifies Rust source files before compilation to produce a unique binary
on each build. Every build has a different SHA256 hash.

What it changes:
    - Injects a random BUILD_ID constant (changes binary content)
    - Randomizes the ASCII banner (changes string table)
    - Adds junk const strings that are referenced in code (not dead code)
    - Shuffles display column widths slightly

This is NOT heavy obfuscation. It defeats simple hash-based detection
(AV signature, IOC matching) without breaking functionality.

Usage:
    python3 scripts/polymorphic.py          # modify in place
    python3 scripts/polymorphic.py --revert # restore originals
"""

import os
import random
import string
import sys
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SCRIPT_DIR)
SRC = os.path.join(ROOT, "src")
BACKUP = os.path.join(ROOT, ".poly_backup")


def random_id(length=32):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def random_banner():
    styles = [
        lambda: f"// {random_id(16)}",
        lambda: f"    [{random_id(8)}] hidemylogs",
        lambda: f"    hidemylogs // build {random_id(12)}",
        lambda: f"    --- hidemylogs {random_id(6)} ---",
    ]
    return random.choice(styles)()


def random_junk_const():
    name = f"_POLY_{random_id(8).upper()}"
    value = random_id(random.randint(16, 48))
    return f'const {name}: &str = "{value}";\n'


def process_main(path):
    with open(path, 'r') as f:
        content = f.read()

    build_id = random_id(32)

    # Use std::hint::black_box to prevent LLVM from optimizing away our values.
    # black_box is specifically designed to be opaque to the optimizer.
    junk_consts = ""
    junk_usage = ""
    for _ in range(random.randint(3, 6)):
        name = f"_POLY_{random_id(8).upper()}"
        value = random_id(random.randint(16, 48))
        junk_consts += f'static {name}: &str = "{value}";\n'
        junk_usage += f'    std::hint::black_box({name});\n'

    inject = f'static _BUILD_ID: &str = "{build_id}";\n{junk_consts}'

    marker = "use std::process;"
    if marker in content:
        content = content.replace(
            marker,
            f"{marker}\n\n{inject}",
            1
        )

    main_marker = "let cli = Cli::parse();"
    if main_marker in content:
        content = content.replace(
            main_marker,
            f"std::hint::black_box(_BUILD_ID);\n{junk_usage}    {main_marker}",
            1
        )

    with open(path, 'w') as f:
        f.write(content)

    return build_id


def process_display(path):
    with open(path, 'r') as f:
        content = f.read()

    # Randomize banner slightly
    new_banner = f'''    let banner = r#"
    [{random_id(8)}] hidemylogs // {random_id(12)}
"#;'''

    # Replace the existing banner block
    import re
    content = re.sub(
        r'let banner = r#".*?"#;',
        new_banner,
        content,
        flags=re.DOTALL
    )

    with open(path, 'w') as f:
        f.write(content)


def backup_sources():
    if os.path.exists(BACKUP):
        shutil.rmtree(BACKUP)
    shutil.copytree(SRC, BACKUP)


def revert_sources():
    if not os.path.exists(BACKUP):
        print("[!] No backup found. Nothing to revert.")
        return False
    shutil.rmtree(SRC)
    shutil.copytree(BACKUP, SRC)
    shutil.rmtree(BACKUP)
    print("[+] Sources reverted to original.")
    return True


def main():
    if "--revert" in sys.argv:
        revert_sources()
        return

    backup_sources()

    build_id = process_main(os.path.join(SRC, "main.rs"))
    process_display(os.path.join(SRC, "display.rs"))

    print(f"[+] Polymorphic build prepared")
    print(f"    Build ID: {build_id}")
    print(f"    Backup:   {BACKUP}")
    print(f"    Revert:   python3 scripts/polymorphic.py --revert")


if __name__ == "__main__":
    main()
