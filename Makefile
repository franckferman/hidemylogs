.PHONY: release poly poly-clean revert

release:
	cargo build --release

poly:
	python3 scripts/polymorphic.py
	RUSTFLAGS="-Ccontrol-flow-guard=no -Cforce-frame-pointers=no" \
		cargo build --profile poly
	python3 scripts/polymorphic.py --revert
	@echo "[+] Polymorphic build: target/poly/hidemylogs"
	@sha256sum target/poly/hidemylogs

poly-clean: poly
	strip target/poly/hidemylogs
	@echo "[+] Stripped."
	@sha256sum target/poly/hidemylogs

revert:
	python3 scripts/polymorphic.py --revert
