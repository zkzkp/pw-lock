/* The script perform secp256k1_keccak256_sighash_all verification. */
#include "ckb_dlfcn.h"
#include "ckb_syscalls.h"
#include "common.h"
#include "protocol.h"
#include "secp256k1_helper.h"
#include "secp256k1_keccak256_sighash_all_lib.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 65  // ETH address uncompress pub key
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

#define MAX_OUTPUT_LENGTH 64

#define ERROR_TOO_MANY_OUTPUT_CELLS -18
#define ERROR_DYNAMIC_LOADING -103

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

/*
 * Arguments:
 * ethereum address, keccak256 hash of pubkey last 20 bytes, used to
 * shield the real pubkey.
 *
 * Witness:
 * WitnessArgs with a signature in lock field used to present ownership.
 */
int main() {
  uint8_t secp_code_buffer[100 * 1024] __attribute__((aligned(RISCV_PGSIZE)));
  uint8_t *aligned_code_start = secp_code_buffer;
  size_t aligned_size = ROUNDDOWN(100 * 1024, RISCV_PGSIZE);

  int ret;
  void *handle = NULL;
  uint64_t consumed_size = 0;
  ret =
      ckb_dlopen(secp256k1_keccak256_sighash_all_lib_data_hash, aligned_code_start,
                 aligned_size, &handle, &consumed_size);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  int (*verify_func)(unsigned char[20]);
  *(void **)(&verify_func) =
      ckb_dlsym(handle, "verify_secp256k1_keccak_sighash_all");
  if (verify_func == NULL) {
    return ERROR_DYNAMIC_LOADING;
  }

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

  return verify_func(args_bytes_seg.ptr);
}
