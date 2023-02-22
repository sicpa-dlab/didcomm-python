"""Print current version of package as GHA output."""

import tomli

with open("pyproject.toml", "rb") as f:
    project = tomli.load(f)

print("::set-output name=current_version::" + project["tool"]["poetry"]["version"])
