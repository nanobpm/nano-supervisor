# D kernel seam (issue #90). Rust (cargo) remains the product build.
.PHONY: generate test check-drift

generate:
	python3 kernel/generate.py

test:
	dub test

check-drift: generate
	git diff --exit-code -- source/nano_sup/kernel.d
