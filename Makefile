.PHONY: fmt fix compile-musl compile-musl-pcap

fmt:
	cargo +nightly fmt

fix:
	__CARGO_FIX_YOLO=1 cargo +nightly fix

compile-musl:
	cargo build --release --target x86_64-unknown-linux-musl

LIBPCAP_VERSION ?= 1.10.5
LIBPCAP_PREFIX ?= $(abspath target/libpcap-musl)
LIBPCAP_CFLAGS ?= -O2 -idirafter /usr/include -idirafter /usr/include/x86_64-linux-gnu

$(LIBPCAP_PREFIX)/lib/libpcap.a:
	mkdir -p target
	curl -fsSL https://www.tcpdump.org/release/libpcap-$(LIBPCAP_VERSION).tar.gz | tar xz -C target
	cd target/libpcap-$(LIBPCAP_VERSION) && \
		CC=musl-gcc CFLAGS="$(LIBPCAP_CFLAGS)" ./configure --prefix=$(LIBPCAP_PREFIX) --disable-shared \
			--disable-dbus --without-libnl --disable-bluetooth --disable-usb --disable-rdma && \
		$(MAKE) && $(MAKE) install

compile-musl-pcap: $(LIBPCAP_PREFIX)/lib/libpcap.a
	LIBPCAP_STATIC=1 LIBPCAP_LIBDIR=$(LIBPCAP_PREFIX)/lib LIBPCAP_VER=$(LIBPCAP_VERSION) \
		cargo build --release --target x86_64-unknown-linux-musl --features pcap
