# Makefile for common tasks in the IronFix Rust workspace.
#
# Portability: every recipe here must run unchanged on macOS (BSD userland) and
# on the Ubuntu runners used by CI. That rules out `sed -i ''`, which GNU sed
# reads as a filename.

# Detect current branch
CURRENT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
ZIP_NAME = IronFix.zip

# The workspace version, read from [workspace.package] in the root Cargo.toml.
# Used for benchmark baseline names and for the crates.io already-published
# check in publish-all, so neither can drift from the real version again.
WORKSPACE_VERSION := $(shell sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)

# Every crate carrying a path+version entry in [workspace.dependencies].
PATH_CRATES := ironfix-core ironfix-dictionary ironfix-tagvalue ironfix-session \
	ironfix-store ironfix-transport ironfix-fast ironfix-codegen ironfix-derive \
	ironfix-engine

# Publication order. A crate must appear after every crate it depends on,
# because crates.io resolves the version requirements at upload time.
PUBLISH_ORDER := ironfix-core ironfix-derive ironfix-tagvalue ironfix-dictionary \
	ironfix-store ironfix-session ironfix-transport ironfix-fast ironfix-codegen \
	ironfix-engine ironfix-example

# crates.io answers 403 to any request without a User-Agent, so the
# already-published probe in publish-all must identify itself.
CRATES_IO_USER_AGENT := ironfix-makefile (jb@taunais.com)

# Set version across all crates
# Usage: make version VERSION=0.1.1
.PHONY: version
version:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make version VERSION=x.y.z"; exit 1; fi
	@echo "$(VERSION)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$$' \
		|| { echo "Invalid VERSION '$(VERSION)': expected x.y.z"; exit 1; }
	@echo "Setting version to $(VERSION) across all crates..."
	@tmp=Cargo.toml.version.tmp; \
	sed 's/^version = "[^"]*"/version = "$(VERSION)"/' Cargo.toml > $$tmp \
		&& cp $$tmp Cargo.toml && rm -f $$tmp
	@for crate in $(PATH_CRATES); do \
		tmp=Cargo.toml.version.tmp; \
		sed "s|^$$crate = { path = \"$$crate\", version = \"[^\"]*\"|$$crate = { path = \"$$crate\", version = \"$(VERSION)\"|" Cargo.toml > $$tmp \
			&& cp $$tmp Cargo.toml && rm -f $$tmp; \
	done
	@applied=$$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1); \
	if [ "$$applied" != "$(VERSION)" ]; then \
		echo "Version rewrite failed: Cargo.toml still reports '$$applied'"; exit 1; \
	fi
	@stale=$$(grep -E '^ironfix-[a-z]+ = \{ path = ' Cargo.toml \
		| grep -v 'version = "$(VERSION)"' || true); \
	if [ -n "$$stale" ]; then \
		echo "Version rewrite incomplete, these entries were not updated:"; \
		echo "$$stale"; \
		exit 1; \
	fi
	@echo "Version updated to $(VERSION)"
	@cargo check --workspace

# Default target
.PHONY: all
all: test fmt lint build

# Build the project
.PHONY: build
build:
	cargo build --workspace

.PHONY: release
release:
	cargo build --release --workspace

# Run tests
.PHONY: test
test:
	LOGLEVEL=WARN cargo test --workspace

# Format the code
.PHONY: fmt
fmt:
	cargo +stable fmt --all

# Check formatting. This is the CI gate: it must never rewrite a file.
.PHONY: fmt-check
fmt-check:
	cargo +stable fmt --all --check

# Run Clippy for linting
.PHONY: lint
lint:
	cargo clippy --all-targets --all-features -- -D warnings

.PHONY: lint-fix
lint-fix:
	cargo clippy --fix --all-targets --all-features --allow-dirty --allow-staged -- -D warnings

# Clean the project
.PHONY: clean
clean:
	cargo clean

# Pre-push checks
.PHONY: check
check: fmt-check lint test doc check-spanish

# Run an example (this workspace has no binary targets)
.PHONY: run
run:
	@if [ -z "$(EXAMPLE)" ]; then \
		echo "This workspace is a library workspace and has no binary targets."; \
		echo "Usage: make run EXAMPLE=<name>"; \
		echo "Available examples:"; \
		ls ironfix-example/examples/*.rs | sed 's|.*/||; s|\.rs$$||; s|^|  |'; \
		exit 1; \
	fi
	cargo run -p ironfix-example --example $(EXAMPLE)

.PHONY: fix
fix:
	cargo fix --allow-staged --allow-dirty

.PHONY: pre-push
pre-push: fix fmt lint-fix test check-spanish readme doc

# Documentation coverage gate. Scoped to library targets: `--all-targets` would
# pull in ironfix-example's examples, which are demo binaries with undocumented
# public fields and are not part of any published API surface.
.PHONY: doc
doc:
	cargo clippy --workspace --all-features --lib -- -D missing_docs

.PHONY: doc-open
doc-open:
	cargo doc --open

.PHONY: publish
publish: readme
	@echo "Publishing to crates.io requires publishing crates in dependency order."
	@echo "Use 'make publish-all' to publish all crates in the correct order."
	@echo "Or publish individual crates with 'make publish-crate CRATE=ironfix-core'"
	@echo ""
	@echo "Both targets read CARGO_REGISTRY_TOKEN from the environment."
	@echo "Preview without touching the registry: make publish-all DRY_RUN=1"

# cargo publish reads CARGO_REGISTRY_TOKEN from the environment directly, so
# there is no `cargo login` step and the token is never expanded into a recipe
# line, a process listing, or a CI log.
.PHONY: require-token
require-token:
	@if [ -z "$$CARGO_REGISTRY_TOKEN" ] && [ -z "$(DRY_RUN)" ]; then \
		echo "CARGO_REGISTRY_TOKEN is not set in the environment."; \
		echo "Export it before publishing; it is never passed on the command line."; \
		exit 1; \
	fi

.PHONY: publish-crate
publish-crate: require-token
	@if [ -z "$(CRATE)" ]; then echo "Usage: make publish-crate CRATE=<crate-name>"; exit 1; fi
	@find . -name ".DS_Store" -type f -delete || true
	cargo package -p $(CRATE)
	@if [ -n "$(DRY_RUN)" ]; then \
		echo "DRY_RUN: would run 'cargo publish -p $(CRATE)' at version $(WORKSPACE_VERSION)"; \
	else \
		cargo publish -p $(CRATE); \
	fi

# Publishes all crates in dependency order, fail-fast.
#
# crates.io versions are immutable, so a partial publish cannot be repaired by
# overwriting: the only safe behaviour is to stop at the first failure and say
# exactly which crates made it and which did not. A crate whose version is
# already on crates.io is skipped, which makes a re-run after a failure
# idempotent.
.PHONY: publish-all
publish-all: require-token readme
	@find . -name ".DS_Store" -type f -delete || true
	@set -u; \
	version='$(WORKSPACE_VERSION)'; \
	if [ -z "$$version" ]; then echo "Cannot read the workspace version from Cargo.toml"; exit 1; fi; \
	total=$(words $(PUBLISH_ORDER)); \
	index=0; \
	published=''; \
	echo "Publishing $$total crates at version $$version in dependency order..."; \
	for crate in $(PUBLISH_ORDER); do \
		index=$$((index + 1)); \
		status=$$(curl -sL -A '$(CRATES_IO_USER_AGENT)' -o /dev/null -w '%{http_code}' \
			"https://crates.io/api/v1/crates/$$crate/$$version" 2>/dev/null || echo 000); \
		if [ "$$status" = "200" ]; then \
			echo "$$index/$$total: $$crate $$version is already on crates.io - skipping"; \
			continue; \
		fi; \
		if [ "$$status" != "404" ]; then \
			echo "$$index/$$total: crates.io returned HTTP $$status for $$crate $$version;"; \
			echo "         cannot tell whether it is already published. Continuing -"; \
			echo "         cargo refuses to overwrite an existing version."; \
		fi; \
		echo "$$index/$$total: publishing $$crate $$version..."; \
		if [ -n "$(DRY_RUN)" ]; then \
			echo "         DRY_RUN: would run 'cargo publish -p $$crate'"; \
		elif ! cargo publish -p "$$crate"; then \
			echo ""; \
			echo "FAILED while publishing $$crate ($$index/$$total)."; \
			echo "  Published in this run: $${published:- none}"; \
			echo "  NOT published:        $$(echo '$(PUBLISH_ORDER)' | tr ' ' '\n' | tail -n +$$index | tr '\n' ' ')"; \
			echo ""; \
			echo "  The registry is now in a partial state. Published versions are"; \
			echo "  immutable: fix the cause and re-run 'make publish-all' - crates"; \
			echo "  already at $$version are skipped automatically."; \
			exit 1; \
		fi; \
		published="$$published $$crate"; \
		if [ "$$index" -lt "$$total" ] && [ -z "$(DRY_RUN)" ]; then sleep 30; fi; \
	done; \
	if [ -n "$(DRY_RUN)" ]; then \
		echo "DRY_RUN complete: previewed $$total crates at $$version; nothing was published."; \
	else \
		echo "Done: all $$total crates are on crates.io at $$version."; \
	fi

.PHONY: check-cargo-tarpaulin
check-cargo-tarpaulin:
	@command -v cargo-tarpaulin > /dev/null || (echo "Installing cargo-tarpaulin..."; cargo install cargo-tarpaulin)

# Each recipe line runs in its own shell, so LOGLEVEL has to be set on the same
# line as the command that reads it.
.PHONY: coverage
coverage: check-cargo-tarpaulin
	@mkdir -p coverage
	LOGLEVEL=WARN cargo tarpaulin --exclude-files 'benches/**' --all-features --workspace --timeout 120 --out Xml

.PHONY: coverage-html
coverage-html: check-cargo-tarpaulin
	@mkdir -p coverage
	LOGLEVEL=WARN cargo tarpaulin --exclude-files 'benches/**' --verbose --all-features --workspace --timeout 120 --out Html --output-dir coverage

.PHONY: coverage-json
coverage-json: check-cargo-tarpaulin
	@mkdir -p coverage
	LOGLEVEL=WARN cargo tarpaulin --exclude-files 'benches/**' --verbose --all-features --workspace --timeout 120 --out Json --output-dir coverage

.PHONY: open-coverage
open-coverage:
	open coverage/tarpaulin-report.html

# Rule to show git log
git-log:
	@if [ "$(CURRENT_BRANCH)" = "HEAD" ]; then \
		echo "You are in a detached HEAD state. Please check out a branch."; \
		exit 1; \
	fi; \
	echo "Showing git log for branch $(CURRENT_BRANCH) against main:"; \
	git log main..$(CURRENT_BRANCH) --pretty=full

.PHONY: create-doc
create-doc:
	cargo doc --no-deps --document-private-items

.PHONY: readme
readme: create-doc
	@echo "README.md already exists (workspace project, cargo-readme not applicable)"

.PHONY: check-cargo-readme
check-cargo-readme:
	@command -v cargo-readme > /dev/null || (echo "Installing cargo-readme..."; cargo install cargo-readme)

# English-only check (rules/global_rules.md).
#
# The word list is deliberately conservative: only words that are unambiguously
# Spanish and have no English, Rust or FIX-jargon collision, and nothing shorter
# than four characters (short words such as `de`, `con` and `no` collide with
# identifiers like serde's `de` and abbreviations like `con`). Accents are not
# used as a signal because the author banner in every file carries them.
#
# To allow a line deliberately, put the marker `spanish-ok` on it.
SPANISH_WORDS := pero|porque|cuando|donde|desde|hasta|entonces|tambien|también|siempre|nunca|mientras|aunque|ademas|además|segun|según|solamente|como|para|que|cada|todos|todas|mismo|misma|nuevo|nueva|primero|ultimo|último|siguiente|anterior|mensaje|mensajes|campo|campos|cabecera|cabeceras|longitud|tamano|tamaño|numero|número|numeros|valor|valores|cadena|cadenas|clave|claves|datos|prueba|pruebas|ejemplo|ejemplos|archivo|archivos|fichero|ficheros|funcion|función|funciones|devuelve|devuelven|retorna|retornan|obtiene|obtener|enviar|envia|envía|recibir|recibe|crear|borrar|guardar|validar|comprobar|verificar|calcular|correcto|incorrecto|fallo|fallos|aviso|advertencia|configuracion|configuración|conexion|conexión|sesion|sesión|servidor|cliente|puerto|paquete|paquetes|inicio|estado|estados|espera|esperar|hilo|hilos|memoria|tiempo|entrada|entradas|salida|salidas|lista|listas|tipo|tipos|nombre|nombres|usuario|contrasena|contraseña|ejecutar|ejecuta|permite|necesita|debe|deben|puede|pueden|tiene|tienen|hacer|hace|usar

.PHONY: check-spanish
check-spanish:
	@hits=$$(grep -rInEw \
		--include='*.rs' --include='*.md' \
		--exclude-dir=target --exclude-dir=.git --exclude-dir=spec \
		-e '($(SPANISH_WORDS))' \
		$(wildcard ironfix-*) doc README.md 2>/dev/null \
		| grep -v 'spanish-ok' || true); \
	if [ -n "$$hits" ]; then \
		echo "check-spanish: Spanish text found. All code, comments and docs must be in English."; \
		echo "$$hits"; \
		echo ""; \
		echo "If a match is a false positive, add the marker 'spanish-ok' to that line."; \
		exit 1; \
	fi; \
	echo "check-spanish: no Spanish words found."

.PHONY: zip
zip:
	@echo "Creating $(ZIP_NAME) without any 'target' directories, 'Cargo.lock', and hidden files..."
	@find . -type f \
		! -path "*/target/*" \
		! -path "./.*" \
		! -name "Cargo.lock" \
		! -name ".*" \
		| zip -@ $(ZIP_NAME)
	@echo "$(ZIP_NAME) created successfully."

# Benchmarks.
#
# These run criterion's own harness through `cargo bench`. The external
# `cargo-criterion` runner was dropped: it has been archived upstream and does
# not understand the message format of current criterion releases, so the old
# `cargo criterion` targets ran nothing while reporting success.
#
# The harness makes measurement possible; it ships no recorded baseline. Any
# figure quoted anywhere in this repository must come from a run you can point
# at, on hardware you name.
BENCH_BASELINE ?= v$(WORKSPACE_VERSION)

# Each criterion benchmark is named explicitly as package:target. `--benches`
# would also select every crate's implicit libtest bench target, and libtest
# rejects criterion's arguments ("error: Unrecognized option: 'quick'"), so any
# target that forwards flags would fail on an unrelated crate.
CRITERION_BENCHES := ironfix-tagvalue:tagvalue ironfix-fast:fast ironfix-transport:framing

# Arguments forwarded to the criterion harness. Set by the wrapper targets
# below; override directly for anything criterion accepts, for example:
#   make bench BENCH_ARGS="--sample-size 500 decode"
BENCH_ARGS ?=

.PHONY: bench
bench:
	@for entry in $(CRITERION_BENCHES); do \
		pkg=$${entry%%:*}; name=$${entry##*:}; \
		echo "==> $$pkg :: $$name"; \
		cargo bench -p "$$pkg" --bench "$$name" -- $(BENCH_ARGS) || exit 1; \
	done

# Compile-only: this is what CI runs, since benchmark timings taken on a shared
# runner are not a measurement.
.PHONY: bench-build
bench-build:
	@for entry in $(CRITERION_BENCHES); do \
		pkg=$${entry%%:*}; name=$${entry##*:}; \
		cargo bench -p "$$pkg" --bench "$$name" --no-run || exit 1; \
	done

# Reduced sample count. A smoke run, not a measurement.
.PHONY: bench-quick
bench-quick:
	@$(MAKE) bench BENCH_ARGS="--quick"

.PHONY: bench-show
bench-show:
	@if [ ! -f target/criterion/report/index.html ]; then \
		echo "No criterion report found. Run 'make bench' first."; \
		exit 1; \
	fi
	@(command -v open > /dev/null && open target/criterion/report/index.html) \
		|| (command -v xdg-open > /dev/null && xdg-open target/criterion/report/index.html) \
		|| echo "Open target/criterion/report/index.html in a browser."

# Records the current run as the baseline named after the workspace version.
# Override with: make bench-save BENCH_BASELINE=my-branch
.PHONY: bench-save
bench-save:
	@$(MAKE) bench BENCH_ARGS="--save-baseline $(BENCH_BASELINE)"

# Compares the current run against a previously saved baseline.
.PHONY: bench-compare
bench-compare:
	@if [ -z "$$(find target/criterion -type d -name '$(BENCH_BASELINE)' 2>/dev/null | head -1)" ]; then \
		echo "No saved baseline named '$(BENCH_BASELINE)'."; \
		echo "Record one first: make bench-save BENCH_BASELINE=$(BENCH_BASELINE)"; \
		exit 1; \
	fi
	@$(MAKE) bench BENCH_ARGS="--baseline $(BENCH_BASELINE)"

.PHONY: bench-clean
bench-clean:
	rm -rf target/criterion

.PHONY: workflow-coverage
workflow-coverage:
	DOCKER_HOST="$${DOCKER_HOST}" act push --job code_coverage_report \
       -P ubuntu-latest=catthehacker/ubuntu:latest \
       --privileged

.PHONY: workflow-build
workflow-build:
	DOCKER_HOST="$${DOCKER_HOST}" act push --job build \
       -P ubuntu-latest=catthehacker/ubuntu:latest

.PHONY: workflow-lint
workflow-lint:
	DOCKER_HOST="$${DOCKER_HOST}" act push --job lint

.PHONY: workflow-test
workflow-test:
	DOCKER_HOST="$${DOCKER_HOST}" act push --job run_tests

.PHONY: workflow
workflow: workflow-build workflow-lint workflow-test workflow-coverage

.PHONY: tree
tree:
	tree -I 'target|.idea|.run|.DS_Store|Cargo.lock|*.md|*.toml|*.zip|*.html|*.xml|*.json|*.txt|*.sh|*.yml|*.yaml|*.gitignore|*.gitattributes|*.gitmodules|*.git|*.gitkeep|*.gitlab-ci.yml' -a -L 3
