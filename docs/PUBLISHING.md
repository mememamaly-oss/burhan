# Packaging and publishing instructions

These commands are intentionally explicit. Run them from a clean checkout and
review the built artifacts before any upload. The repository does not publish
to PyPI or GHCR automatically; publication remains an owner decision.

## Local package validation

```bash
python3 -m venv /tmp/burhan-package-check
. /tmp/burhan-package-check/bin/activate
python -m pip install --upgrade pip
python -m pip install .
burhan doctor
python -m pip show burhan-scanner
deactivate
rm -rf /tmp/burhan-package-check
```

## Docker validation against a local target

```bash
docker build --tag burhan:local .
docker run --rm --network host \
  --user 10001:10001 \
  --volume burhan-owner-gate:/var/lib/burhan \
  burhan:local owner init --password 'CHANGE-ME-ONLY-FOR-LOCAL-TEST'
docker run --rm --network host \
  --user 10001:10001 \
  --volume burhan-owner-gate:/var/lib/burhan \
  --env BURHAN_OWNER_PASSWORD='CHANGE-ME-ONLY-FOR-LOCAL-TEST' \
  burhan:local scan http://127.0.0.1:8777 --allow-private \
  --out /tmp/burhan-result.json
```

The local fixture must already be running on `127.0.0.1:8777`. On Docker
Desktop, use the platform-specific host gateway instead of `--network host` and
keep the target inside the local development set.

## PyPI publication (owner-operated)

```bash
python3 -m venv /tmp/burhan-release
. /tmp/burhan-release/bin/activate
python -m pip install --upgrade pip build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/*
deactivate
```

Do not put a token in the repository, shell history, or command line. Configure
the approved PyPI credential through the owner’s credential manager or an
interactive keyring before running `twine upload`.

## GHCR publication (owner-operated)

```bash
docker build --tag ghcr.io/OWNER/burhan:VERSION .
echo "$CR_PAT" | docker login ghcr.io --username OWNER --password-stdin
docker push ghcr.io/OWNER/burhan:VERSION
```

Replace `OWNER` and `VERSION` only after reviewing the image digest and the
release notes. Never paste a personal access token into this file or a commit.
