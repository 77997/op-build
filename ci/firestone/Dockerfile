FROM ubuntu:20.04@sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a

LABEL org.opencontainers.image.source="https://github.com/77997/op-build"
LABEL org.opencontainers.image.description="op-build CI container for firestone_defconfig (ubuntu:20.04 amd64)"

ARG BUILDER_UID
ARG BUILDER_GID

RUN test -n "${BUILDER_UID}" && test -n "${BUILDER_GID}"

RUN sed -e 's/main$/main universe/' --in-place=orig /etc/apt/sources.list
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yy --no-install-recommends \
          cscope ctags libz-dev libexpat-dev \
          python-is-python3 language-pack-en texinfo gawk cpio xxd \
          build-essential g++ git bison flex unzip \
          libssl-dev libxml-simple-perl libxml-sax-perl libxml-parser-perl libxml2-dev libxml2-utils xsltproc \
          wget bc rsync \
          eatmydata python3-matplotlib python3-scipy graphviz bsdmainutils lsb-release \
          libxml-libxml-perl libc6-dev file xz-utils bzip2 patch perl python3 \
          locales ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN locale-gen en_US.UTF-8 && \
    update-locale LANG=en_US.UTF-8 && \
    locale -a | grep -qx 'en_US.utf8'

RUN perl -MXML::LibXML -MXML::Simple -MXML::Parser -MIPC::Cmd -MMath::BigInt \
         -MDigest::SHA -MDigest::MD5 -MData::Dumper -MThread::Queue -MFindBin \
         -MEnglish -MExtUtils::MakeMaker -MEnv -e 1 && \
    command -v yacc && command -v bison && command -v flex && \
    command -v ctags && command -v cscope && command -v xxd && \
    test -f /usr/lib/x86_64-linux-gnu/libc.a

RUN git config --system --add safe.directory '*'

RUN if ! getent group "${BUILDER_GID}" > /dev/null; then \
        groupadd --gid "${BUILDER_GID}" builder; \
    fi && \
    useradd --uid "${BUILDER_UID}" --gid "${BUILDER_GID}" --create-home --shell /bin/bash builder

ENV LANG=en_US.UTF-8
USER builder
WORKDIR /home/builder
