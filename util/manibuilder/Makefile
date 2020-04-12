QUIET_TEST := @

include Makefile.targets

CC := ccache cc
MAKECMD := make
MAKEARGS := CONFIG_EVERYTHING=yes

spc :=
spc := $(spc) $(spc)

stem = $(word 1,$(subst :,$(spc),$(subst \:,$(spc),$(1))))
ident = $(subst :,_,$(subst \:,_,$(1)))

include Makefile.anita

define build_template
Dockerfile.$(call ident,$(1)): Dockerfile.$(call stem,$(1)) mani-wrapper.sh
	$(QUIET_SETUP)sed -e 's|^FROM manibase|FROM $(2)/$(1)|' $$< >$$@

.INTERMEDIATE: Dockerfile.$(call ident,$(1))

$(1)-build: Dockerfile.$(call ident,$(1))
	$(QUIET_SETUP)docker build . -f $$< -t mani/$(1) $$(DOCKER_BUILD_ARGS)
endef

$(foreach tag,$(MULTIARCH_TAGS), \
	$(eval $(call build_template,$(tag),multiarch)))

$(addsuffix -build,$(filter alpine%v3.7 alpine%v3.8,$(MULTIARCH_TAGS))): \
	DOCKER_BUILD_ARGS = --build-arg PROTO=http

djgpp\:6.1.0-build: %-build: Dockerfile.djgpp mani-wrapper.sh
	$(QUIET_SETUP)docker build . -f $< -t mani/$*

git-check-build $(addsuffix -check-build,$(ALL_TAGS)): %-check-build:
	$(QUIET_SETUP)\
	[ $$(docker image ls -q mani/$*) ] \
		|| $(MAKE) $*-build $(if $(QUIET_SETUP),>/dev/null 2>/dev/null)

$(filter centos%,$(MULTIARCH_TAGS)) anita\:7.1-sparc: CC=cc
djgpp\:6.1.0: CC=ccache i586-pc-msdosdjgpp-gcc
djgpp\:6.1.0: STRIP=i586-pc-msdosdjgpp-strip
djgpp\:6.1.0: LIBS_BASE=../
djgpp\:6.1.0: MAKEARGS+=strip CONFIG_JLINK_SPI=no
$(ANITA_TAGS): MAKECMD=gmake
$(ANITA_TAGS): MAKEARGS+=CONFIG_JLINK_SPI=no WARNERROR=no
$(filter alpine% centos%,$(MULTIARCH_TAGS)): MAKEARGS+=CONFIG_JLINK_SPI=no
$(filter %-xenial %-stretch,$(MULTIARCH_TAGS)): MAKEARGS+=CONFIG_JLINK_SPI=no
$(filter centos%,$(MULTIARCH_TAGS)): MAKEARGS+=WARNERROR=no
$(ALL_TAGS): export QUIET_SETUP=$(QUIET_TEST)
$(ALL_TAGS): export TEST_REMOTE?=$(if $(TEST_LOCAL),\
					git://mani-git/flashrom.git,\
					origin)
$(ALL_TAGS): export TEST_REVISION?=$(if $(TEST_LOCAL),HEAD,master)
$(ALL_TAGS): %: %-check-build mani-net $(if $(TEST_LOCAL),local-git)
	$(QUIET_TEST)docker rm -f mani_$(call ident,$*) >/dev/null 2>&1 || true
	$(QUIET_TEST)\
	docker run \
		$(MANI_DOCKER_ARGS) \
		--env IDENT=$(call ident,$*) \
		--volume manicache:/home/mani/.ccache \
		--network=manibuilder \
		--name mani_$(call ident,$*) mani/$* \
		"git fetch $(TEST_REMOTE) $(TEST_REVISION) && \
		 git checkout FETCH_HEAD && \
		 $(MAKECMD) clean && $(MAKECMD) -j$${CPUS:-1} CC='$(CC)' \
		 $(if $(STRIP),STRIP='$(STRIP)') \
		 $(if $(LIBS_BASE),LIBS_BASE='$(LIBS_BASE)') \
		 $(MAKEARGS)" \
		$(if $(QUIET_TEST),>/dev/null 2>&1) \
			|| { RET=$$?; echo $*: $${RET}; exit $${RET}; }

$(addsuffix -shell,$(ALL_TAGS)): %-shell: %-check-build
	$(QUIET_SETUP)\
	if [ $$(docker ps -a -q -f name=mani_$(call ident,$*)) ]; then \
		docker commit mani_$(call ident,$*) mani_run/$* && \
		docker run --rm -it \
			$(MANI_DOCKER_ARGS) \
			--env IDENT=$(call ident,$*) \
			--volume manicache:/home/mani/.ccache \
			--network=manibuilder \
			--entrypoint /bin/sh mani_run/$* \
			/home/mani/mani-wrapper.sh \
			$(patsubst %,"%",$(SHELL_ARG)); \
		docker image rm mani_run/$*; \
	else \
		docker run --rm -it \
			$(MANI_DOCKER_ARGS) \
			--env IDENT=$(call ident,$*) \
			--volume manicache:/home/mani/.ccache \
			--network=manibuilder \
			mani/$* $(patsubst %,"%",$(SHELL_ARG)); \
	fi

.PHONY: $(foreach s,-build -check-build -shell, $(addsuffix $(s),$(ALL_TAGS)))

register:
	docker build . \
		-f Dockerfile.qemu-user-static \
		-t mani/qemu-user-static:register
	docker run --rm --privileged mani/qemu-user-static:register --reset

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
		--volume=$(TEST_LOCAL_GIT):/git/flashrom.git:ro \
		--network=manibuilder \
		mani/git $(if $(QUIET_SETUP),>/dev/null)

.PHONY: register mani-net git-build local-git