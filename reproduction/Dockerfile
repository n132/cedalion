# The environment repro.sh needs, pinned, so that "it reproduces" is a claim
# someone else can check rather than one about this machine. Everything a bug
# publishes -- reproducer, config, qemu line -- is fetched at run time; what is
# baked in is everything that is the same for every bug: the toolchain, qemu,
# the kernelCTF image the bugs boot on, and a bare clone of mainline. So the
# image is large and building it is slow, once, and after that a bug costs its
# own build and nothing else -- and `docker save` hands all of it to someone
# who then needs the network for three files.
#
# repro.sh builds this on first use and runs itself inside it; there is nothing
# to do by hand. It runs as the invoking uid with the current directory bind
# mounted at /work, so the kernel tree and bzImage it leaves there belong to
# you and not to root, and /work is all the container can see.
FROM ubuntu:24.04

# dwarves is pahole, for configs that turn on CONFIG_DEBUG_INFO_BTF; the rest
# is what building a mainline x86_64 kernel and booting it under qemu takes.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
	bc \
	bison \
	build-essential \
	ca-certificates \
	cpio \
	curl \
	dwarves \
	flex \
	git \
	gzip \
	kmod \
	libelf-dev \
	libssl-dev \
	python3 \
	qemu-system-x86 \
	rsync \
	xz-utils \
	zstd \
	&& rm -rf /var/lib/apt/lists/*

# The reproducer image every published run.sh expects to find as rootfs.img.
# Baked in rather than fetched per run: it is the one artifact that is the same
# for every bug, and having it here is what makes a saved image self-contained.
RUN mkdir -p /opt/cedalion && \
	curl -fL https://storage.googleapis.com/kernelctf-build/files/rootfs_repro_v2.img.gz \
	     -o /opt/cedalion/rootfs.img.gz && \
	gzip -d /opt/cedalion/rootfs.img.gz && \
	chmod 644 /opt/cedalion/rootfs.img

# Mainline, bare, as a layer. This is the expensive part of reproducing a bug
# that has nothing to do with which bug it is: every checkout in every work
# directory comes out of this one object store, so it is cloned when the image
# is built rather than once per directory that ever runs a bug.
#
# It ages, of course. A commit newer than the image is not here, and repro.sh
# fetches that one into the bug's own clone, which is writable -- this stays
# read-only and shared. Rebuild the image to move the floor up.
#
# safe.directory because the clone belongs to root and the container runs as
# the caller, which git otherwise refuses to read.
RUN git clone --quiet --bare \
	https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git \
	/opt/cedalion/linux.git && \
	git config --system --add safe.directory /opt/cedalion/linux.git
ENV CEDALION_LINUX_CACHE=/opt/cedalion/linux.git

COPY repro.sh /usr/local/bin/repro.sh

ENV CEDALION_ROOTFS=/opt/cedalion/rootfs.img
# What repro.sh reads to know it is already on the inside and should get on
# with the work rather than starting a container of its own.
ENV CEDALION_IN_CONTAINER=1
# The container runs as the caller's uid, which has no passwd entry and so no
# home; git and make want one, and /work is the bind mount that always exists.
ENV HOME=/work
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/repro.sh"]
