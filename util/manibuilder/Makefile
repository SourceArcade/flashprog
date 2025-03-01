QUIET_TEST := @

include Makefile.targets

CC := ccache cc
MAKECMD := make
MAKEARGS := CONFIG_EVERYTHING=yes
MESONCMD := meson
MESONARGS := -D programmer=all -D classic_cli_print_wiki=enabled --auto-features enabled

spc :=
spc := $(spc) $(spc)

# Replace %$(2) -> %/$(2), e.g. armv5 with arm/v5 etc.
preproc_subst = $(if $(2),$(call preproc_arch,$(patsubst %$(2),%/$(2),$(1)),$(3)),$(1))
preproc_arch = $(call preproc_subst,$(1),$(firstword $(2)),$(wordlist 2,$(words $(2)),$(2)))

# Get stem of multiarch tags of the form `stem[-variation]:arch-version`
ma_stem = $(word 1,$(subst -,$(spc),$(subst :,$(spc),$(subst \:,$(spc),$(1)))))
# Get stem of official tags of the form `arch/stem:version`
official_stem = $(word 2,$(subst /,$(spc),$(subst :,$(spc),$(subst \:,$(spc),$(1)))))
# Get arch prefix of official tags
official_arch = $(word 1,$(subst /,$(spc),$(1)))
# Create a platform string from the arch prefix, e.g. arm32v5 -> linux/arm/v5
official_plat = linux/$(patsubst arm32%,arm%,$(call preproc_arch,$(call official_arch,$(1)),v5 v6 v7 v8))

ident = $(subst /,_,$(subst :,_,$(subst \:,_,$(1))))

include Makefile.env
include Makefile.anita
include Makefile.cross

# $(1): mani tag
# $(2): from tag
# $(3): Dockerfile suffix
# $(4): platform            (optional)
define build_template
Dockerfile.$(call ident,$(1)): Dockerfile.$(3) mani-wrapper.sh
	$(QUIET_SETUP)sed -e 's|^FROM manibase|FROM $(2)|' $$< >$$@

.INTERMEDIATE: Dockerfile.$(call ident,$(1))

$(1)-build: Dockerfile.$(call ident,$(1)) source-check-build
	$(QUIET_SETUP)docker build . \
		$(addprefix --platform$(spc),$(4)) -f $$< -t mani/$(1) \
		--build-arg IDENT=$(call ident,$(1)) $$(DOCKER_BUILD_ARGS)
endef

$(foreach tag,$(MULTIARCH_TAGS), \
	$(eval $(call build_template,$(tag),multiarch/$(tag),$(call ma_stem,$(tag)))))

$(foreach tag,$(OFFICIAL_TAGS), \
	$(eval $(call build_template,$(tag),$(tag),$(call official_stem,$(tag)),$(call official_plat,$(tag)))))

djgpp\:6.1.0-build: %-build: Dockerfile.djgpp mani-wrapper.sh
	$(QUIET_SETUP)docker build . -f $< -t mani/$* --build-arg IDENT=$(call ident,$*)

source-build: Dockerfile.source
	$(QUIET_SETUP)\
		SRC_TMP=$$(mktemp -d -p .) && \
		{ git clone $${TEST_LOCAL:-../../} $${SRC_TMP} && \
		  docker build . --build-arg SRC_TMP=$${SRC_TMP} -f $< -t mani/source; \
		  rm -rf $${SRC_TMP}; }

$(addsuffix -check-build,source git cross $(NONCROSS_TAGS)): %-check-build:
	$(QUIET_SETUP)\
	[ $$(docker image ls -q mani/$*) ] \
		|| $(MAKE) $*-build $(if $(QUIET_SETUP),>/dev/null 2>/dev/null)
$(addsuffix -check-build,$(CROSS_TAGS)): cross-check-build

$(ALL_TAGS): export QUIET_SETUP=$(QUIET_TEST)
$(ALL_TAGS): export TEST_REMOTE?=$(if $(TEST_LOCAL),\
					git://mani-git/flashprog.git,\
					https://review.sourcearcade.org/flashprog.git)
$(ALL_TAGS): export TEST_REVISION?=$(if $(TEST_LOCAL),HEAD,main)
$(ALL_TAGS): %: %-check-build mani-net $(if $(TEST_LOCAL),local-git)
	$(QUIET_TEST)docker rm -f mani_$(call ident,$*) >/dev/null 2>&1 || true
	$(QUIET_TEST)\
	docker run \
		$(MANI_DOCKER_ARGS) \
		--env IDENT=$(call ident,$*) \
		--volume manicache:/ccache \
		--network=manibuilder \
		--name mani_$(call ident,$*) mani/$(patsubst cross-%,cross,$*) \
		"git fetch $(TEST_REMOTE) $(TEST_REVISION) && \
		 git checkout FETCH_HEAD && \
		 export CC='$(CC)' STRIP='$(STRIP)' LIBS_BASE='$(LIBS_BASE)' && \
		 export MAKECMD='$(MAKECMD)' MAKEARGS='$(subst ',\\\",$(MAKEARGS))' && \
		 export MESONCMD='$(MESONCMD)' MESONARGS='$(subst ',\\\",$(MESONARGS))' && \
		 export CPUS=$${CPUS:-1} $(ENV_VARS) && \
		 ./test_build.sh" \
		$(if $(QUIET_TEST),>/dev/null 2>&1) \
			|| { RET=$$?; echo $*: $${RET}; exit $${RET}; }

$(addsuffix -shell,$(ALL_TAGS)): %-shell: %-check-build
	$(QUIET_SETUP)\
	if [ $$(docker ps -a -q -f name=mani_$(call ident,$*)) ]; then \
		docker commit mani_$(call ident,$*) mani_run/$* && \
		docker run --rm -it \
			$(MANI_DOCKER_ARGS) \
			--env IDENT=$(call ident,$*) \
			--volume manicache:/ccache \
			--network=manibuilder \
			--entrypoint /bin/sh mani_run/$* \
			/home/mani/mani-wrapper.sh \
			$(patsubst %,"%",$(SHELL_ARG)); \
		docker image rm mani_run/$*; \
	else \
		docker run --rm -it \
			$(MANI_DOCKER_ARGS) \
			--env IDENT=$(call ident,$*) \
			--volume manicache:/ccache \
			--network=manibuilder \
			mani/$(patsubst cross-%,cross,$*) \
			$(patsubst %,"%",$(SHELL_ARG)); \
	fi

.PHONY: $(foreach s,-build -check-build -shell, $(addsuffix $(s),$(ALL_TAGS)))

register:
	docker build . \
		-f Dockerfile.qemu-user-static \
		-t mani/qemu-user-static
	docker run --rm --privileged mani/qemu-user-static --reset -p yes

mani-net:
	$(QUIET_SETUP)\
	if [ -z "$$(docker network ls -qf name=manibuilder)" ]; then \
		docker network create manibuilder \
			$(if $(QUIET_SETUP),>/dev/null); \
	fi

git-build: Dockerfile.git
	$(QUIET_SETUP)docker build . -f $< -t mani/git

local-git: TEST_LOCAL_GIT:=$(abspath $(wildcard \
		$(TEST_LOCAL)$(if $(filter %.git,$(TEST_LOCAL)),,/.git)))
local-git: git-check-build mani-net
	$(QUIET_SETUP)\
	if [ -z "$(TEST_LOCAL_GIT)" ]; then \
		echo '$${TEST_LOCAL} should point to a Git repository.'; \
		exit 1; \
	fi; \
	if [ -n "$$(docker container ls -qf name=mani-git)" ]; then \
		if docker inspect -f '{{ .Mounts }}' mani-git | \
				grep -q ' $(TEST_LOCAL_GIT) '; then \
			exit 0; \
		else \
			docker stop mani-git >/dev/null; \
		fi; \
	fi; \
	docker run --rm --detach \
		--name mani-git \
		--volume=$(TEST_LOCAL_GIT):/git/flashprog.git:ro \
		--network=manibuilder \
		mani/git $(if $(QUIET_SETUP),>/dev/null)

.PHONY: register mani-net git-build local-git
