import json, os, re, subprocess, tempfile, pathlib, textwrap, shutil
from typing import List
from rich import print
from rich.table import Table
from git import Repo
from tree_sitter import Language, Parser
import typer, requests, openai

app = typer.Typer()
OPENAI = os.getenv("OPENAI_API_KEY")

# -- load Tree-sitter JS grammar once
LANG_PATH = "build/languages.so"
if not pathlib.Path(LANG_PATH).exists():
    Language.build_library(LANG_PATH, ["vendor/tree-sitter-javascript"])
TS_JS = Language(LANG_PATH, "javascript")
parser = Parser(); parser.set_language(TS_JS)

RISK_REGEX = re.compile(r"(fix|patch|vuln|cve|security)", re.I)
DANGEROUS_NODES = {"call_expression": {"eval", "Function", "exec"}}

def parse_package_json(p):
    data = json.load(open(p))
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    out = []
    for name, ver in deps.items():
        meta = requests.get(f"https://registry.npmjs.org/{name}").json()
        git_url = meta.get("repository", {}).get("url", "")
        out.append({"name": name, "version": ver.strip("^~"), "git": git_url.replace("git+", "")})
    return out

def scan_repo(dep):
    tmp = tempfile.mkdtemp()
    Repo.clone_from(dep["git"], tmp, depth=50)
    repo = Repo(tmp)
    commits = list(repo.iter_commits(max_count=50))
    latest_tag = subprocess.check_output(["git", "tag", "--sort=-creatordate"], cwd=tmp).splitlines()
    latest_tag = latest_tag[0].decode() if latest_tag else None
    hits = []
    for c in commits:
        if RISK_REGEX.search(c.message):
            diff = repo.git.show(c.hexsha, "--unified=0", "--no-color")
            risky = any(tok.decode() in b"+ eval" for tok in diff.encode().split(b"\n"))
            hits.append({"sha": c.hexsha[:7], "msg": c.message.split("\n")[0], "risky": risky})
            if len(hits) == 3: break
    shutil.rmtree(tmp)
    return hits, latest_tag

@app.command()
def scan(path: str = "package.json"):
    deps = parse_package_json(path)
    table = Table(title="PatchFrame findings"); table.add_column("Dep"); table.add_column("Issue")
    report = []
    for d in deps:
        hits, tag = scan_repo(d)
        if hits:
            table.add_row(d["name"], f"{len(hits)} suspicious patch(es)")
            if OPENAI:
                txt = openai.ChatCompletion.create(
                    model="gpt-4o-mini",
                    messages=[{"role":"user","content":f"Summarize security relevance of {hits} in 2 sentences."}],
                    max_tokens=100
                ).choices[0].message.content
            else:
                txt = "GPT summary skipped."
            report.append({**d, "hits": hits, "summary": txt, "latest_tag": tag})
    print(table)
    pathlib.Path("dist").mkdir(exist_ok=True)
    json.dump(report, open("dist/report.json","w"), indent=2)
    print("[green]JSON saved to dist/report.json")

if __name__ == "__main__":
    app()
