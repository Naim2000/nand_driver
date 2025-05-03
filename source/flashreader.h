#include "common.h"
#include "structures.h"

typedef struct NandHandle {
    FILE*           fp;
    size_t          filesize;
    int             has_spare: 1;
    int             has_keys: 1;

    uint32_t        bad_block_map[NAND_BLOCK_COUNT / 32];

    uint32_t        boot1_hash[5];
    uint32_t        common_key[4];
    uint32_t        nandfs_aes_key[4];
    uint32_t        nandfs_hmac_key[5];

    SFFSSuperblock  superblock;
    int             superblock_idx;
} NandHandle;

int  Nand_Init(NandHandle*, const char* filepath, const char* keys_path);
void Nand_Close(NandHandle*);

int  Nand_ReadPages(NandHandle*, unsigned page, unsigned count, unsigned char data[count][NAND_PAGE_SIZE]);
