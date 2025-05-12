#include <stdio.h>
#include <getopt.h>
#include <endian.h>

#include "common.h"
#include "flashreader.h"

int main(int argc, const char* const argv[]) {
    NandHandle nand;

    int ret = Nand_Init(&nand, argv[1], 0);

    Nand_PickSuperblock(&nand);

    Nand_Close(&nand);

    return ret;
}
