FROM buildpack-deps:jessie

RUN apt-get update && apt-get install -y gdb

ADD vendor/openssl-fips-2.0.14 /openssl-fips-2.0.14
RUN cd /openssl-fips-2.0.14 && ./config -d && make && make install
ADD vendor/openssl-1.0.2k /openssl-1.0.2k
RUN cd /openssl-1.0.2k && ./config -d fips && make depend && make && make install

# Build test suite
RUN cd /openssl-fips-2.0.14 && make build_tests

# Add test vectors
ADD testvectors-linux-2007-10-10.tar.gz /openssl-fips-2.0.14

ENV PKG_CONFIG_PATH "/usr/local/ssl/lib/pkgconfig"
ENV CC "/usr/local/ssl/fips-2.0/bin/fipsld"
ENV FIPSLD_CC "gcc"

WORKDIR /root/src
ADD . .
