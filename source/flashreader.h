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

int     Nand_Init(NandHandle* handle, const char* filepath, const char* keys_path);
void    Nand_Close(NandHandle* handle);

int     Nand_ReadPages(NandHandle* handle, unsigned page, unsigned count, unsigned char* data, bool spare);
int     Nand_ReadClusters(NandHandle* handle, unsigned start, unsigned count, int flags, const unsigned char* iv, const unsigned char* salt, unsigned salt_len, unsigned char* data);
int     Nand_PickSuperblock(NandHandle* handle);

typedef struct SFFSStats {
    unsigned cluster_size;
    unsigned used_clusters, free_clusters, bad_clusters, reserved_clusters, erased_clusters /* ?? */;
    unsigned used_inodes, free_inodes;
    unsigned total_files_size;
} SFFSStats;

int     Nand_StatFilesystem(NandHandle* handle, SFFSStats* out);

int     Nand_FindInode(NandHandle* handle, unsigned inode, const char* path);
int     Nand_FindPath(NandHandle* handle, const char* path);

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

int   Nand_OpenInode(NandHandle* handle, unsigned inode, NandFile* fp);
void  Nand_CloseFile(NandHandle* handle, NandFile* fp);
int   Nand_ReadFileA(NandHandle* handle, NandFile* fp, unsigned char* data, unsigned offset, unsigned len);

typedef struct NandDirEnt {
    char      name[SFFS_FST_MAXNAMELEN + 1];
    unsigned  inode;
    int       type;
    unsigned  mode;
    uint32_t  uid;
    uint16_t  gid;
    unsigned  filesize;
} NandDirEnt;

typedef struct NandDirectory {
    unsigned   inode;
    unsigned   cur;
    NandDirEnt buf;
} NandDirectory;

int         Nand_OpenDir(NandHandle* handle, unsigned inode, NandDirectory* dirp);
NandDirEnt* Nand_ReadDir(NandHandle* handle, NandDirectory* dirp);
void        Nand_RewindDir(NandHandle* handle, NandDirectory* dirp);
