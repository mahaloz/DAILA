FROM --platform=linux/amd64 ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# install java, python, and some utils
RUN apt-get update && apt-get -o APT::Immediate-Configure=0 install -y \
      python3-dev python3-pip openjdk-17-jdk unzip sed wget \
    && rm -rf /var/lib/apt/lists/*

# install ghidra 10.4 and patch the launch script to work in containers
RUN mkdir tools && mkdir /root/ghidra_scripts/
ENV PATH "/tools/:$PATH"
WORKDIR tools
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1_build/ghidra_11.1_PUBLIC_20240607.zip && \
    unzip ghidra_11.1_PUBLIC_20240607.zip && \
    sed -i 's/java -cp/java -Djdk.lang.Process.launchMechanism=vfork -cp/g' /tools/ghidra_11.1_PUBLIC/support/launch.sh

# copy the local pip project, install it, its plugins, and the models
workdir /
COPY . /DAILA/
RUN pip3 install --upgrade pip \
    && pip3 install -e ./DAILA[full] \
    && daila --single-decompiler-install ghidra /root/ghidra_scripts/

