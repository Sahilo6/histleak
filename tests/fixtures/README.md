# packed_git/

A pre-built, fully-packed bare repository used as test data. It is committed as-is so the
test suite never shells out to `git` at run time and has zero dependency, including on `git`
itself, at test time.

It was built once, outside the test run, with:

```bash
git init
git config user.email "fixture@histleak.test"
git config user.name "histleak fixture"

GIT_AUTHOR_DATE=2024-01-01T00:00:00 GIT_COMMITTER_DATE=2024-01-01T00:00:00 \
  git commit --allow-empty -q -m "initial commit"   # (README.md added here in practice)

# a fake AWS key, added...
GIT_AUTHOR_DATE=2024-01-02T00:00:00 GIT_COMMITTER_DATE=2024-01-02T00:00:00 \
  git commit -q -m "add prod config (oops)"         # config/prod.env

# ...and deleted in a later commit, so it only survives in history
GIT_AUTHOR_DATE=2024-01-03T00:00:00 GIT_COMMITTER_DATE=2024-01-03T00:00:00 \
  git commit -q -m "remove leaked config"

GIT_AUTHOR_DATE=2024-01-04T00:00:00 GIT_COMMITTER_DATE=2024-01-04T00:00:00 \
  git commit -q -m "add app code"                   # app.py, unrelated

git gc --aggressive   # forces everything into a packfile with a delta chain
```

`config/prod.env` contained `AWS_SECRET_ACCESS_KEY=AKIAFAKEFAKEFAKE0001`, a syntactically valid
but fake AWS access key id. It is present only in history, never in the working tree, which is
exactly the case `histleak` is built to catch.

Only `HEAD`, `objects/`, `refs/`, and `packed-refs` are kept. `hooks/`, `index`, `logs/`,
`description`, and `config` were stripped since `histleak` never reads them.
