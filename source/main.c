#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <endian.h>

#include "common.h"
#include "flashreader.h"
#include "structures.h"

int main(int argc, const char* const argv[]) {
    int        ret;
    NandHandle nand;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <nand.bin> [path ...]\n", argv[0]);
        return -1;
    }

    ret = Nand_Init(&nand, argv[1], 0);
    ret = Nand_PickSuperblock(&nand);
    Nand_StatFilesystem(&nand, 0);
    for (int i = 2; i < argc; i++) {
        int inode = Nand_FindPath(&nand, argv[i]);
        debug_printf(0, "Nand_FindPath(%s) -> %#x", argv[i], inode);
        if (inode != SFFS_FST_EOF) {
            SFFSFstEnt* entry = &nand.superblock->fst[inode];

            if ((entry->mode & SFFS_FST_TYPE_MASK) == SFFS_FST_TYPE_FILE) {
                NandFile fp = {};
                ret = Nand_OpenInode(&nand, inode, &fp);
                debug_printf(0, "Nand_OpenInode() -> %i", ret);
                if (ret == 0) {
                    unsigned char* data = malloc(fp.fsize);
                    ret = Nand_ReadFileA(&nand, &fp, data, 0, fp.fsize);
                    // hexdump("Data", data, fp.fsize);

                    const char* filename = strrchr(argv[i], '/') + 1;
                    FILE* fpw = fopen(filename, "wb");
                    if (fpw) {
                        fwrite(data, fp.fsize, 1, fpw);
                        fclose(fpw);
                    }

                    free(data);
                }
                Nand_CloseFile(&nand, &fp);
            } else if ((entry->mode & SFFS_FST_TYPE_MASK) == SFFS_FST_TYPE_DIR) {
                NandDirectory dirp = {};

                ret = Nand_OpenDir(&nand, inode, &dirp);
                debug_printf(0, "Nand_OpenDir() -> %i", ret);
                if (ret == 0) {
                    NandDirEnt* pent;
                    while ((pent = Nand_ReadDir(&nand, &dirp)) != NULL) {
                        debug_printf(0, "entry '%s', type %u, uid %#x, gid %#x, size %#x", pent->name, pent->type, pent->uid, pent->gid, pent->filesize);
                    }
                }
            }

        }
    }

    Nand_Close(&nand);

    return ret;
}
