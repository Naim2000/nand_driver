#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <endian.h>

#include "common.h"
#include "flashreader.h"

int main(int argc, const char* const argv[]) {
    int        ret;
    NandHandle nand;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <nand.bin> <filepath> [filepath ...]\n", argv[0]);
        return -1;
    }

    ret = Nand_Init(&nand, argv[1], 0);
    ret = Nand_PickSuperblock(&nand);
    for (int i = 2; i < argc; i++) {
        int inode = Nand_FindInode(&nand, argv[i]);
        debug_printf(0, "Nand_FindInode(%s) -> %#x", argv[i], inode);
        if (inode != SFFS_FST_EOF) {
            SFFSFstEnt* entry = &nand.superblock->fst[inode];
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
        }
    }


    Nand_Close(&nand);

    return ret;
}
