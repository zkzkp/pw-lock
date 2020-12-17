// # secp256k1-blake160-sighash-all-dual
//
// This is the same lock script code as the system
// [secp256k1-blake160-sighash-all](https://github.com/nervosnetwork/ckb-system-scripts/blob/9c1fca3246903adbb5c516f16404212c03dd3a01/c/secp256k1_blake160_sighash_all.c)
// with one additional feature: it can be executed as a standalone lock
// script. At the same time, it can also be included as a library via dynamic
// linking techniques. This enables us to share the secp256k1 logic between many
// on chain smart contracts.
//
// As a result, we will only document the newly affected features. Please refer
// to the original script for how the signature verification logic works.

// One noticable addition here, is that we are including `ckb_dlfcn.h` library.
// This provides dynamic linking related features.
#include "protocol.h"
#include "keccak256.h"
#include "ckb_dlfcn.h"
#include "ckb_syscalls.h"
#include "ckb_utils.h"
#include "secp256k1_helper.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define UNCOMPRESSED_PUBKEY_SIZE 65  // ETH address uncompress pub key
#define RECID_INDEX 64
#define SIGNATURE_SIZE 65
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define TEMP_SIZE 32768
#define KECCAK256_HASH_SIZE 32
#define ETH_ADDRESS_SIZE 20

#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SECP_RECOVER_PUBKEY -11
#define ERROR_SECP_VERIFICATION -12
#define ERROR_SECP_PARSE_PUBKEY -13
#define ERROR_SECP_PARSE_SIGNATURE -14
#define ERROR_SECP_SERIALIZE_PUBKEY -15
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_WITNESS_SIZE -22
#define ERROR_PUBKEY_ETH_ADDRESS -31
#define ERROR_INVALID_PREFILLED_DATA_SIZE -41
#define ERROR_INVALID_SIGNATURE_SIZE -42
#define ERROR_INVALID_MESSAGE_SIZE -43
#define ERROR_INVALID_OUTPUT_SIZE -44

// Extract lock from WitnessArgs
int extract_witness_lock(uint8_t *witness, uint64_t len,
                         mol_seg_t *lock_bytes_seg) {
  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t lock_seg = MolReader_WitnessArgs_get_lock(&witness_seg);

  if (MolReader_BytesOpt_is_none(&lock_seg)) {
    return ERROR_ENCODING;
  }
  *lock_bytes_seg = MolReader_Bytes_raw_bytes(&lock_seg);
  return CKB_SUCCESS;
}

int bin2hex(uint8_t *bin, uint8_t len, char* out)
{
	uint8_t  i;
	for (i=0; i<len; i++) {
		out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
		out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
	}
	out[len*2] = '\0';
    return 0;
}

__attribute__((visibility("default")))
int signature_message(
        uint8_t output_signature[SIGNATURE_SIZE],
        uint8_t output_message[KECCAK256_HASH_SIZE]) {

  int ret;
  uint64_t len = 0;
  unsigned char temp[TEMP_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];

  /* Load witness of first input */
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != CKB_SUCCESS) {
    return ERROR_ENCODING;
  }

  if (lock_bytes_seg.size != SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(lock_bytes, lock_bytes_seg.ptr, lock_bytes_seg.size);

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  /* Prepare sign message */
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  keccak_update(&sha3_ctx, (unsigned char *)&witness_len, sizeof(uint64_t));
  keccak_update(&sha3_ctx, temp, witness_len);

  /* Digest same group witnesses */
  size_t i = 1;
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }

    keccak_update(&sha3_ctx, (unsigned char *)&len, sizeof(uint64_t));
    keccak_update(&sha3_ctx, temp, len);
    i += 1;
  }

  /* Digest witnesses that not covered by inputs */
  i = ckb_calculate_inputs_len();
  while (1) {
    len = MAX_WITNESS_SIZE;
    ret = ckb_load_witness(temp, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    if (len > MAX_WITNESS_SIZE) {
      return ERROR_WITNESS_SIZE;
    }

    keccak_update(&sha3_ctx, (unsigned char *)&len, sizeof(uint64_t));
    keccak_update(&sha3_ctx, temp, len);
    i += 1;
  }

  keccak_final(&sha3_ctx, message);

  /* personal hash, ethereum prefix  \u0019Ethereum Signed Message:\n32  */
  unsigned char eth_prefix[28] = {0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65,
                                  0x75, 0x6d, 0x20, 0x53, 0x69, 0x67, 0x6e,
                                  0x65, 0x64, 0x20, 0x4d, 0x65, 0x73, 0x73,
                                  0x61, 0x67, 0x65, 0x3a, 0x0a, 0x33, 0x32};

  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, eth_prefix, 28);
  keccak_update(&sha3_ctx, message, 32);
  keccak_final(&sha3_ctx, message);

  memcpy(output_signature, lock_bytes_seg.ptr, lock_bytes_seg.size);
  memcpy(output_message, message, KECCAK256_HASH_SIZE);

  return CKB_SUCCESS;
}

__attribute__((visibility("default"))) int validate_signature(
    const uint8_t signature_buffer[SIGNATURE_SIZE],
    const uint8_t message_buffer[KECCAK256_HASH_SIZE],
    uint8_t output_uncompressed_pubkey[UNCOMPRESSED_PUBKEY_SIZE]) {
  int ret;

  // NOTE: ckb_secp256k1_custom_verify_only_initialize fn will implicitly
  // load secp_data in pw-lock included secp256k1_helper.h
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  secp256k1_context context;
  ret =
      ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, signature_buffer,
          signature_buffer[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message_buffer) !=
      1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  size_t pubkey_size = UNCOMPRESSED_PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, output_uncompressed_pubkey, &pubkey_size, &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  return CKB_SUCCESS;
}

// Given a keccak256 format public key hash, this method performs signature
// verifications on input cells using current lock script hash. It then asserts
// that the derive public key hash from the signature matches the given public
// key hash.
//
// Note that this method is exposed for dynamic linking usage, so the
// "current lock script" mentioned above, does not have to be this current
// script code. It could be a different script code using this script via as a
// library.
__attribute__((visibility("default"))) int
verify_secp256k1_keccak_sighash_all(uint8_t output_eth_address[ETH_ADDRESS_SIZE]) {
  int ret;

  // Collect message and its signature
  uint8_t signature[SIGNATURE_SIZE];
  uint8_t message[KECCAK256_HASH_SIZE];
  ret = signature_message(signature, message);
  if (ret != CKB_SUCCESS) {
      return ret;
  }

  // Validate signature and recovery uncompressed pubkey
  uint8_t uncompressed_pubkey[UNCOMPRESSED_PUBKEY_SIZE];
  ret = validate_signature(signature, message, uncompressed_pubkey);

  // Generate eth address from uncompressed pubkey
  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, &uncompressed_pubkey[1], UNCOMPRESSED_PUBKEY_SIZE - 1);

  unsigned char pubkey_hash[KECCAK256_HASH_SIZE];
  keccak_final(&sha3_ctx, pubkey_hash);

  memcpy(output_eth_address, pubkey_hash, ETH_ADDRESS_SIZE);
  return CKB_SUCCESS;
}

// This replicates the same validation logic as the system
// secp256k1-blake160-sighash-all script. It loads public key hash from the
// witness of the same index as the first input using current lock script.
// Then using this public key hash, we are doing signature verification on input
// cells using current lock script.
//
// Note that this method is exposed for dynamic linking usage, so the
// "current lock script" mentioned above, does not have to be this current
// script code. It could be a different script code using this script via as a
// library.
__attribute__((visibility("default"))) int lock_validation() {
  int ret;
  uint64_t len = 0;

  // Load args
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != BLAKE160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  uint8_t eth_address[ETH_ADDRESS_SIZE];
  ret = verify_secp256k1_keccak_sighash_all(eth_address);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  char address[ETH_ADDRESS_SIZE * 2];
  char expected_address[ETH_ADDRESS_SIZE * 2];
  bin2hex(eth_address, ETH_ADDRESS_SIZE, address);
  bin2hex(args_bytes_seg.ptr, ETH_ADDRESS_SIZE, expected_address);
  ckb_debug(address);
  ckb_debug(expected_address);

  if (memcmp(args_bytes_seg.ptr, eth_address, ETH_ADDRESS_SIZE) != 0) {
    return ERROR_PUBKEY_ETH_ADDRESS;
  }

  return CKB_SUCCESS;
}

#define OFFSETOF(TYPE, ELEMENT) ((size_t) & (((TYPE *)0)->ELEMENT))
#define PT_DYNAMIC 2

typedef struct {
  uint64_t type;
  uint64_t value;
} Elf64_Dynamic;

// A simply inlined program interpreter. This works when the lock script is
// used as an executable on its own.
//
// Assuming ELF header lives at 0x0, also avoiding deferencing
// NULL pointer.
int main() {
  uint64_t *phoff = (uint64_t *)OFFSETOF(Elf64_Ehdr, e_phoff);
  uint16_t *phnum = (uint16_t *)OFFSETOF(Elf64_Ehdr, e_phnum);
  Elf64_Phdr *program_headers = (Elf64_Phdr *)(*phoff);
  ;
  for (int i = 0; i < *phnum; i++) {
    Elf64_Phdr *program_header = &program_headers[i];
    if (program_header->p_type == PT_DYNAMIC) {
      Elf64_Dynamic *d = (Elf64_Dynamic *)program_header->p_vaddr;
      uint64_t rela_address = 0;
      uint64_t rela_count = 0;
      while (d->type != 0) {
        if (d->type == 0x7) {
          rela_address = d->value;
        } else if (d->type == 0x6ffffff9) {
          rela_count = d->value;
        }
        d++;
      }
      if (rela_address > 0 && rela_count > 0) {
        Elf64_Rela *relocations = (Elf64_Rela *)rela_address;
        for (int j = 0; j < rela_count; j++) {
          Elf64_Rela *relocation = &relocations[j];
          if (relocation->r_info != R_RISCV_RELATIVE) {
            return ERROR_INVALID_ELF;
          }
          *((uint64_t *)(relocation->r_offset)) =
              (uint64_t)(relocation->r_addend);
        }
      }
    }
  }

  return lock_validation();
}
