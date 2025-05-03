#include <stdio.h>
#include <getopt.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha1.h>

#include "common.h"
#include "flashreader.h"

int main(int argc, const char* const argv[]) {
    NandHandle* nand = malloc(sizeof *nand);
    int ret = Nand_Init(nand, argv[1], 0);

    SFFSSuperblock* sblock = malloc(sizeof *sblock);

    ret = Nand_ReadPages(nand, NAND_PAGE_COUNT - ( 16 * sizeof *sblock / NAND_PAGE_SIZE ), sizeof *sblock / NAND_PAGE_SIZE, sblock);
    FILE* fp = fopen("superblock.img", "wb");
    if (fp) {
        fwrite(sblock, sizeof *sblock, 1, fp);
        fclose(fp);
    }

    free(sblock);

    Nand_Close(nand);
    free(nand);

    return ret;
}
