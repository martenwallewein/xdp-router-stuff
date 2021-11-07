FROM ubuntu:20.10
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install make git build-essential clang llvm libbpf-dev libelf-dev  -y
RUN apt-get install libelf-dev libc6-dev-i386 iproute2 libpcap-dev gcc-multilib linux-tools-common linux-tools-generic -y
RUN apt-get install -y pkg-config
RUN cp -R /usr/include/x86_64-linux-gnu/asm /usr/include/linux/

WORKDIR /tmp
RUN git clone https://github.com/xdp-project/xdp-tools
WORKDIR /tmp/xdp-tools
RUN ls -lash
RUN apt-get install -y m4
RUN bash ./configure
RUN make 
RUN make install
WORKDIR /app
RUN git clone https://github.com/xdp-project/xdp-tutorial
WORKDIR /app/xdp-tutorial
RUN git submodule update --init
WORKDIR /app/xdp-tutorial/advanced03-AF_XDP
COPY src .
# RUN make -C /lib/modules/$(uname -r)/build/tools/lib/bpf/
RUN make 
ENTRYPOINT ["./af_xdp_user"]
