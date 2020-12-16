TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy
CFLAGS := -fPIC -O3 -nostdlib -nostartfiles -fvisibility=hidden -Ideps/molecule -I deps/secp256k1/src -I deps/secp256k1 -I deps/ckb-c-std-lib -I deps/ckb-c-std-lib/libc -I c -I build -Wall -Werror -Wno-nonnull -Wno-nonnull-compare -Wno-unused-function -g
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
SECP256K1_SRC := deps/secp256k1/src/ecmult_static_pre_context.h
MOLC := moleculec
MOLC_VERSION := 0.4.1
PROTOCOL_HEADER := c/protocol.h
PROTOCOL_SCHEMA := c/blockchain.mol
PROTOCOL_VERSION := d75e4c56ffa40e17fd2fe477da3f98c5578edcd1
PROTOCOL_URL := https://raw.githubusercontent.com/nervosnetwork/ckb/${PROTOCOL_VERSION}/util/types/schemas/blockchain.mol

# docker pull nervos/ckb-riscv-gnu-toolchain:gnu-bionic-20191012
BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

all: specs/cells/ckb_cell_upgrade specs/cells/secp256k1_keccak256_sighash_all  specs/cells/secp256k1_keccak256_sighash_all_acpl specs/cells/secp256k1_keccak256_sighash_all_lib.so build/generate_data_hash c/secp256k1_keccak256_sighash_all_lib.h specs/cells/secp256k1_keccak256_sighash_all_lib_tester

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

specs/cells/secp256k1_keccak256_sighash_all_lib_tester: c/secp256k1_keccak256_sighash_all_lib_tester.c c/secp256k1_keccak256_sighash_all_lib.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

specs/cells/secp256k1_keccak256_sighash_all_lib.so: c/secp256k1_keccak256_sighash_all_lib.c build/secp256k1_data_info.h
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@

c/secp256k1_keccak256_sighash_all_lib.h: build/generate_data_hash specs/cells/secp256k1_keccak256_sighash_all_lib.so
	$< specs/cells/secp256k1_keccak256_sighash_all_lib.so secp256k1_keccak256_sighash_all_lib_data_hash > $@

specs/cells/secp256k1_keccak256_sighash_all: c/secp256k1_keccak256_sighash_all.c ${PROTOCOL_HEADER} c/keccak256.h c/common.h c/utils.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

specs/cells/secp256k1_keccak256_sighash_all_acpl: c/secp256k1_keccak256_sighash_all_acpl.c ${PROTOCOL_HEADER} c/keccak256.h c/common.h c/utils.h build/secp256k1_data_info.h $(SECP256K1_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

specs/cells/ckb_cell_upgrade: c/ckb_cell_upgrade.c ${PROTOCOL_HEADER}
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(OBJCOPY) --only-keep-debug $@ $(subst specs/cells,build,$@.debug)
	$(OBJCOPY) --strip-debug --strip-all $@

build/secp256k1_data_info.h: build/dump_secp256k1_data
	$<

build/dump_secp256k1_data: c/dump_secp256k1_data.c $(SECP256K1_SRC)
	mkdir -p build
	gcc -O3 -I deps/secp256k1/src -I deps/secp256k1 -o $@ $<

build/generate_data_hash: c/generate_data_hash.c
	gcc -O3 -I c -o $@ $<

$(SECP256K1_SRC):
	cd deps/secp256k1 && \
		./autogen.sh && \
		CC=$(CC) LD=$(LD) ./configure --with-bignum=no --enable-ecmult-static-precomputation --enable-endomorphism --enable-module-recovery --host=$(TARGET) && \
		make src/ecmult_static_pre_context.h src/ecmult_static_context.h

generate-protocol: check-moleculec-version ${PROTOCOL_HEADER}

check-moleculec-version:
	test "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" = ${MOLC_VERSION}

${PROTOCOL_HEADER}: ${PROTOCOL_SCHEMA}
	${MOLC} --language c --schema-file $< > $@

${PROTOCOL_SCHEMA}:
	curl -L -o $@ ${PROTOCOL_URL}

install-tools:
	if [ ! -x "$$(command -v "${MOLC}")" ] \
			|| [ "$$(${MOLC} --version | awk '{ print $$2 }' | tr -d ' ')" != "${MOLC_VERSION}" ]; then \
		cargo install --force --version "${MOLC_VERSION}" "${MOLC}"; \
	fi

publish:
	git diff --exit-code Cargo.toml
	sed -i.bak 's/.*git =/# &/' Cargo.toml
	cargo publish --allow-dirty
	git checkout Cargo.toml Cargo.lock
	rm -f Cargo.toml.bak

package:
	git diff --exit-code Cargo.toml
	sed -i.bak 's/.*git =/# &/' Cargo.toml
	cargo package --allow-dirty
	git checkout Cargo.toml Cargo.lock
	rm -f Cargo.toml.bak

package-clean:
	git checkout Cargo.toml Cargo.lock
	rm -rf Cargo.toml.bak target/package/

clean:
	rm -rf ${PROTOCOL_HEADER} ${PROTOCOL_SCHEMA}
	rm -rf specs/cells/ckb_cell_upgrade  specs/cells/secp256k1_keccak256_sighash_all  specs/cells/secp256k1_keccak256_sighash_all_acpl
	rm -rf build/secp256k1_data_info.h build/dump_secp256k1_data
	rm -rf specs/cells/secp256k1_data
	rm -rf build/*.debug
	cd deps/secp256k1 && [ -f "Makefile" ] && make clean
	cargo clean

fmt:
	clang-format -i -style=Google $(wildcard c/*.h c/*.c)
	# git diff --exit-code $(wildcard c/*.h c/*.c)

dist: clean all

.PHONY: all all-via-docker dist clean package-clean package publish
