# SkillTrust
#
# The client is the product; this delegates to it. There was once a Python control plane here
# with its own toolchain, and the top-level targets were about that. It described a system
# with TUF roots, a private ACME CA and a transparency log, none of which was ever built, so
# it was removed rather than left to imply otherwise.
.PHONY: check plugin reproducible clean

check:
	$(MAKE) -C client check

plugin:
	$(MAKE) -C client plugin

reproducible:
	$(MAKE) -C client reproducible

clean:
	$(MAKE) -C client clean
