/* The script perform secp256k1_keccak256_sighash_all verification. */
#include "ckb_dlfcn.h"
#include "ckb_syscalls.h"
#include "ckb_utils.h"
#include "common.h"
#include "keccak256.h"
#include "protocol.h"
#include "secp256k1_helper.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 65  // ETH address uncompress pub key
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65
#define ETH_ADDRESS_SIZE 20

#define MAX_OUTPUT_LENGTH 64

#define ERROR_TOO_MANY_OUTPUT_CELLS -18

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

// FIXME: EIP712 typed data hash
/*
 * Verify the transaction using secp256k1 as sig algorithm and keccak256 as hash
 * algorithm.
 *
 * Since not all ethereum wallets support EIP712, the verification will support
 * two hashes for transaction, both of them are ok.
 * 1. ethereum peronsal hash
 * 2. EIP712 typed data hash
 *
 * Arguments:
 * eth_address, keccak256 hash of pubkey last 20 bytes, used to shield the real
 * pubkey.
 *
 * Witness:
 * WitnessArgs with a signature in lock field used to present ownership.
 */
__attribute__((visibility("default"))) int validate(const uint8_t *lock_args, uint64_t lock_args_size) {
  if (lock_args_size != ETH_ADDRESS_SIZE) {
      return ERROR_ARGUMENTS_LEN;
  }

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

  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, witness_len, &lock_bytes_seg);
  if (ret != 0) {
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

  keccak_init(&sha3_ctx);
  /* personal hash, ethereum prefix  \u0019Ethereum Signed Message:\n32  */
  unsigned char eth_prefix[28] = {0x19, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65,
                                  0x75, 0x6d, 0x20, 0x53, 0x69, 0x67, 0x6e,
                                  0x65, 0x64, 0x20, 0x4d, 0x65, 0x73, 0x73,
                                  0x61, 0x67, 0x65, 0x3a, 0x0a, 0x33, 0x32};
  keccak_update(&sha3_ctx, eth_prefix, 28);
  keccak_update(&sha3_ctx, message, 32);
  keccak_final(&sha3_ctx, message);

  // Load signature
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, lock_bytes, lock_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  // Recover pubkey
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  // Check pubkey hash
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_UNCOMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, &temp[1], pubkey_size - 1);
  keccak_final(&sha3_ctx, temp);

  if (memcmp(lock_args, &temp[12], ETH_ADDRESS_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return CKB_SUCCESS;
}

#define OFFSETOF(TYPE, ELEMENT) ((size_t) & (((TYPE *)0)->ELEMENT))
#define PT_DYNAMIC 2

typedef struct {
  uint64_t type;
  uint64_t value;
} Elf64_Dynamic;

/*
 * Arguments:
 * ethereum address, keccak256 hash of pubkey last 20 bytes, used to
 * shield the real pubkey.
 *
 * Witness:
 * WitnessArgs with a signature in lock field used to present ownership.
 */
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

  int ret;
  uint64_t len = 0;

  /* Load args */
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

  return validate(args_bytes_seg.ptr, args_bytes_seg.size);
}
