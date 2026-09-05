# SkillTrust
#
# The client is the product; this delegates to it. There was once a Python control plane here
# with its own toolchain, and the top-level targets were about that. It described a system
# with TUF roots, a private ACME CA and a transparency log, none of which was ever built, so
# it was removed rather than left to imply otherwise.
.PHONY: check plugin reproducible clean mutation

check:
	$(MAKE) -C client check

plugin:
	$(MAKE) -C client plugin

reproducible:
	$(MAKE) -C client reproducible

clean:
	$(MAKE) -C client clean

# Focused, deterministic fault injections. Copies source into a temporary tree;
# never edits the checkout and never counts compile failures as killed mutants.
mutation:
	go run ./tools/mutation -config mutation.json -output mutation-results.json
