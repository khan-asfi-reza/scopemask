# scopemask developer tasks. Run `just` to list, `just test` to test everything.

default:
    @just --list

# run every language's test suite
test: test-go test-py test-js

test-go:
    cd go && go vet ./... && go test ./...

test-py:
    cd python && uv run pytest

test-js:
    cd js && npm ci && npm run typecheck && npm test

# python across all supported versions (3.10-3.14)
tox:
    cd python && uv run tox

# coverage for every language
cov:
    cd go && go test -cover ./...
    cd python && uv run pytest --cov=scopemask --cov-report=term-missing
    cd js && npm run test:coverage

# build every language artifact
build:
    cd go && go build ./...
    cd python && uv build
    cd js && npm run build

# serve the docs site locally
docs:
    uvx --python 3.13 --with-requirements docs/requirements.txt mkdocs serve -f mkdocs.yml
