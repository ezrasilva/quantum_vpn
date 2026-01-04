FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. Instalar dependências
RUN apt-get update && apt-get install -y \
    strongswan \
    strongswan-pki \
    strongswan-swanctl \
    libcharon-extra-plugins \
    iproute2 \
    iputils-ping \
    kmod \
    nano \
    python3 \
    python3-pip \
    python3-venv \
    git \
    cmake \
    gcc \
    libssl-dev \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# 2. Compilar e Instalar liboqs (Biblioteca C)
WORKDIR /opt
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git \
    && cd liboqs \
    && mkdir build && cd build \
    && cmake -GNinja -DOQS_USE_OPENSSL=1 -DCMAKE_INSTALL_PREFIX=/usr/local .. \
    && ninja \
    && ninja install \
    && ldconfig

# Configurar variáveis de ambiente para liboqs
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

# 3. Instalar liboqs-python (Wrapper Python Oficial)
WORKDIR /opt
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs-python.git \
    && cd liboqs-python \
    && pip3 install .

# 4. Instalar outras libs Python (Cryptography e VICI)
RUN pip3 install cryptography vici

# 5. Voltar para o diretório padrão e rodar o Charon
WORKDIR /
CMD ["/usr/lib/ipsec/charon"]