BIN_NAME=sdpctl
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
GORELEASER_CROSS_VERSION=v1.18.3
DESTDIR :=
prefix  := /usr/local
bindir  := ${prefix}/bin
commit=$$(git rev-parse HEAD)
commitPath=github.com/appgate/sdpctl/cmd.commit=${commit}

CGO := 0
ifeq ($(shell uname),Darwin)
	CGO = 1
endif

.PHONY: build
build:
	CGO_ENABLED=$(CGO) go build -o build/$(BIN_NAME) -ldflags="-X '${commitPath}'"

.PHONY: deps
deps:
	mkdir -p build
	go run main.go completion bash > build/bash_completion
	go run main.go generate man

snapshot: clean
	goreleaser release --snapshot --rm-dist

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

fmt:
	gofmt -w $(GOFMT_FILES)

# Run go test twice, since -race don't catch all edge cases
test:
	go test ./... -count 1 -timeout 30s
	go test ./... -race -covermode=atomic -coverprofile=cover.out -timeout 60s

cover: test
	go tool cover -func cover.out

clean:
	rm -rf build dist cover.out

.PHONY: install
install: build
	install -d ${DESTDIR}${bindir}
	install -m755 build/$(BIN_NAME) ${DESTDIR}${bindir}/

.PHONY: release-dry-run
release-dry-run:
	docker run \
		--rm \
		--env-file .release-env \
		-v $(PWD):/go/src/github.com/user/repo \
		-w /go/src/github.com/user/repo \
		goreleaser/goreleaser-cross:$(GORELEASER_CROSS_VERSION) \
		--skip-validate --rm-dist --skip-publish

.PHONY: release
release:
	@if [ ! -f ".release-env" ]; then \
		echo "\033[91m.release-env is required for release\033[0m";\
		exit 1;\
	fi
	docker run \
        --rm \
        --env-file .release-env \
		-v $(PWD):/go/src/github.com/user/repo \
		-w /go/src/github.com/user/repo \
		goreleaser/goreleaser-cross:$(GORELEASER_CROSS_VERSION) \
		release --rm-dist
