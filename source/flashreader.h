#include "common.h"
#include "structures.h"

typedef struct NandHandle {
    FILE*           fp;
    size_t          filesize;
    int             has_keys: 1;

    // uint32_t        bad_block_map[NAND_BLOCK_COUNT / 32];

    uint8_t         boot1_hash[20];
    uint8_t         common_key[16];
    uint8_t         nandfs_aes_key[16];
    uint8_t         nandfs_hmac_key[20];

    SFFSSuperblock* superblock;
} NandHandle;

int     Nand_Init(NandHandle*, const char* filepath, const char* keys_path);
void    Nand_Close(NandHandle*);

int     Nand_ReadPages(NandHandle*, unsigned page, unsigned count, unsigned char* data, bool spare);
int     Nand_ReadClusters(NandHandle*, unsigned start, unsigned count, int flags, const unsigned char* iv, const unsigned char* salt, unsigned salt_len, unsigned char* data);
int     Nand_PickSuperblock(NandHandle*);
int     Nand_FindInode(NandHandle*, const char* path);

typedef struct NandFile {
    int            ret;
    unsigned       inode;
    uint32_t       fpos;
    uint32_t       fsize;
    SFFSFatEnt*    cltbl;
    unsigned       nclust; // *

    unsigned char* buffer;
    uint32_t       buffer_offset;
} NandFile;

int Nand_OpenInode(NandHandle* handle, unsigned inode, NandFile* fp);
int Nand_ReadFileA(NandHandle* handle, NandFile* fp, unsigned char* data, unsigned offset, unsigned len);
