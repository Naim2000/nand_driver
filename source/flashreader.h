#include "common.h"
#include "structures.h"

typedef struct NandHandle {
    FILE*           fp;
    size_t          filesize;
    int             has_keys;

    KeysBin         keys;

    SFFSSuperblock* superblock;
} NandHandle;

int     Nand_Init(NandHandle* handle, const char* filepath);
void    Nand_Close(NandHandle* handle);
int     Nand_ImportKeys(NandHandle* handle, const char* keys_filepath);

int     Nand_ReadPages(NandHandle* handle, unsigned page, unsigned count, unsigned char* data, bool spare);
int     Nand_ReadClusters(NandHandle* handle, unsigned start, unsigned count, int flags, const unsigned char* iv, const unsigned char* salt, unsigned salt_len, unsigned char* data);

typedef struct NandFSStats {
    unsigned cluster_size;
    unsigned used_clusters, free_clusters, bad_clusters, reserved_clusters, erased_clusters /* ?? */;
    unsigned used_inodes, free_inodes;
    unsigned total_files_size;
} NandFSStats;

int     Nand_PickSuperblock(NandHandle* handle);
int     Nand_StatFilesystem(NandHandle* handle, NandFSStats* out);

int     Nand_FindInode(NandHandle* handle, unsigned inode, const char* path);
int     Nand_FindPath(NandHandle* handle, const char* path);

typedef struct NandFile {
    int            ret;
    unsigned       inode;
    unsigned       fpos;
    unsigned       fsize;
    SFFSFatEnt*    cltbl;
    unsigned       nclust; // *

    unsigned char* buffer;
    unsigned       buffer_offset;
} NandFile;

int     Nand_OpenFileInode(NandHandle* handle, unsigned inode, NandFile* fp);
int     Nand_OpenFile(NandHandle* handle, const char* path, NandFile* fp);
void    Nand_CloseFile(NandHandle* handle, NandFile* fp);
int     Nand_ReadFileA(NandHandle* handle, NandFile* fp, unsigned offset, unsigned char* data, unsigned len);
int     Nand_ReadFile(NandHandle* handle, NandFile* fp, unsigned char* data, unsigned len);
int     Nand_SeekFile(NandHandle* handle, NandFile* fp, int where, int whence);

typedef struct NandFileStat {
    char      name[SFFS_FST_MAXNAMELEN + 1];
    unsigned  inode;
    int       type;
    unsigned  mode;
    uint32_t  uid;
    uint16_t  gid;
    unsigned  filesize;
} NandFileStat, NandDirEnt;

typedef struct NandDirectory {
    unsigned   inode;
    unsigned   cur;
    NandDirEnt buf;
} NandDirectory;

int         Nand_StatInode(NandHandle* handle, unsigned inode, NandFileStat* st);
int         Nand_OpenDirInode(NandHandle* handle, unsigned inode, NandDirectory* dirp);
int         Nand_OpenDir(NandHandle* handle, const char* dirpath, NandDirectory* dirp);
NandDirEnt* Nand_ReadDir(NandHandle* handle, NandDirectory* dirp, NandDirEnt* pent);
void        Nand_RewindDir(NandHandle* handle, NandDirectory* dirp);
