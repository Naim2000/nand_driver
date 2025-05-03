#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <endian.h>
#include <errno.h>

#include "flashreader.h"
#include "common.h"
#include "structures.h"

#define printf_err(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define puts_err(s) fputs(s, stderr)

int Nand_Init(NandHandle* handle, const char* filepath, const char* keys_filepath) {
    my_assert((handle != NULL) && (filepath != NULL));

    handle->fp = fopen(filepath, "rb");
    if (!handle->fp) {
        perror(filepath);
        return -errno;
    }

    fseek(handle->fp, 0, SEEK_END);
    handle->filesize = (size_t)ftell(handle->fp);
    debug_printf(3, "handle->filesize = %#zx", handle->filesize);
    fseek(handle->fp, 0, SEEK_SET);

    if (handle->filesize != NAND_SIZE && handle->filesize != NAND_SIZE_SPARE && handle->filesize != (NAND_SIZE_SPARE + sizeof(KeysBin))) {
        puts_err("This doesn't seem like a NAND backup");
        Nand_Close(handle);
        return -EINVAL;
    }

    handle->has_spare = handle->filesize >= NAND_SIZE_SPARE;

    KeysBin* keys = malloc(sizeof *keys);
    my_assert(keys != NULL);

    if (handle->filesize == (NAND_SIZE_SPARE + sizeof(KeysBin))) {
        fseek(handle->fp, NAND_SIZE_SPARE, SEEK_SET);
        fread(keys, sizeof(KeysBin), 1, handle->fp);
        handle->has_keys = true;
    }
    else if (keys_filepath != NULL) {
        FILE* fp = fopen(keys_filepath, "rb");
        if (!fp) {
            perror(keys_filepath);
            Nand_Close(handle);
            return -errno;
        }

        fread(keys, sizeof(KeysBin), 1, fp);
        fclose(fp);
        handle->has_keys = true;
    } else {
        handle->has_keys = false;
    };

    if (handle->has_keys) {
        debug_printf(3, "we got keys!\n%s", keys->comment);
        memcpy(handle->boot1_hash,      keys->otp.boot1_hash,      sizeof(handle->boot1_hash));
        memcpy(handle->common_key,      keys->otp.common_key,      sizeof(handle->common_key));
        memcpy(handle->nandfs_aes_key,  keys->otp.nandfs_key,      sizeof(handle->nandfs_aes_key));
        memcpy(handle->nandfs_hmac_key, keys->otp.nandfs_hmac_key, sizeof(handle->nandfs_hmac_key));

        debug_printf(3, "common key: %08x%08x%08x%08x", be32toh(handle->common_key[0]), be32toh(handle->common_key[1]), be32toh(handle->common_key[2]), be32toh(handle->common_key[3]));
        debug_printf(3, "boot1 hash: %08x%08x%08x%08x%08x", be32toh(handle->boot1_hash[0]), be32toh(handle->boot1_hash[1]), be32toh(handle->boot1_hash[2]), be32toh(handle->boot1_hash[3]), be32toh(handle->boot1_hash[4]));
    }

    free(keys);
    keys = NULL;

    return 0;
}

void Nand_Close(NandHandle* handle) {
    if (!handle) return;

    if (handle->fp != NULL) {
        fclose(handle->fp);
        handle->fp = NULL;
    }
}

static void calc_ecc(unsigned char *data, unsigned char ecc[4])
{
	unsigned char a[12][2];
	int i, j;
	unsigned a0, a1;
	unsigned char x;

	memset(a, 0, sizeof a);
	for (i = 0; i < 512; i++) {
		for (j = 0; j < 9; j++)
			a[3+j][(i >> j) & 1] ^= data[i];
	}

	x = a[3][0] ^ a[3][1];
	a[0][0] = x & 0x55;
	a[0][1] = x & 0xaa;
	a[1][0] = x & 0x33;
	a[1][1] = x & 0xcc;
	a[2][0] = x & 0x0f;
	a[2][1] = x & 0xf0;

	for (j = 0; j < 12; j++) {
		a[j][0] = __builtin_parity(a[j][0]);
		a[j][1] = __builtin_parity(a[j][1]);
	}

	a0 = a1 = 0;
	for (j = 0; j < 12; j++) {
		a0 |= a[j][0] << j;
		a1 |= a[j][1] << j;
	}

	ecc[0] = a0;
	ecc[1] = a0 >> 8;
	ecc[2] = a1;
	ecc[3] = a1 >> 8;
}

int check_page(unsigned char *page)
{
    unsigned char *spare        = page + NAND_PAGE_SIZE;

    if (spare[0] != 0xFF)
        return -13;

    int ret = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char (*ecc_data)[0x200] = (unsigned char (*)[0x200])page;
        unsigned char (*ecc_read)[4] = (unsigned char (*)[4])(spare + NAND_SPARE_SIZE - 0x10);
        unsigned char   ecc_calc[4];

        if (memcmp(ecc_read[i], (unsigned char[4]){0xFF, 0xFF, 0xFF, 0xFF}, sizeof ecc_read[i]) == 0) // Erased
            continue;

        calc_ecc(ecc_data[i], ecc_calc);
        if (memcmp(ecc_read[i], ecc_calc, sizeof ecc_calc) == 0) // Good
            continue;

        debug_printf(1, "ECC error detected (%i), can't solve it rn", i);
        debug_printf(1, "ecc_read: %02x%02x%02x%02x\n", ecc_read[i][0], ecc_read[i][1], ecc_read[i][2], ecc_read[i][3]);
        debug_printf(1, "ecc_calc: %02x%02x%02x%02x\n", ecc_calc[0],    ecc_calc[1],    ecc_calc[2],    ecc_calc[3]   );
        ret = -12;

        continue;
    }

    return ret;
}

int Nand_ReadPages(NandHandle* handle, unsigned page, unsigned count, unsigned char (*data)[NAND_PAGE_SIZE]) {
    my_assert(handle != NULL && handle->fp != NULL && data != NULL);

    my_assert(page + count <= NAND_PAGE_COUNT);

    unsigned ss = handle->has_spare ? NAND_PAGE_SPARE : NAND_PAGE_SIZE;
    fseek(handle->fp, page * ss, SEEK_SET);

    if (!handle->has_spare) {
        size_t read = fread(data, ss, count, handle->fp);
        if (read != count) {
            int _errno = errno;
            debug_printf(1, "fread() failure, errno=%i (%s)", _errno, strerror(_errno));
            return -1;
        }

        return 0;
    }

    unsigned char (*buffer)[NAND_PAGE_SPARE] = calloc(count, ss);
    my_assert(buffer != NULL);

    size_t read = fread(buffer, ss, count, handle->fp);
    if (read != count) {
        int _errno = errno;
        debug_printf(1, "fread() failure, ernro=%i (%s)", _errno, strerror(_errno));
        return -1;
    }

    for (unsigned i = 0; i < count; i++) {
        int ret = check_page(buffer[i]);
        if (ret != 0)
            debug_printf(0, "check_page() failed (ret=%i)", ret);

        memcpy(data[i], buffer[i], NAND_PAGE_SIZE);
    }

    return 0;
}

int Nand_ReadClusters(NandHandle* handle, unsigned start, unsigned count, int flags, unsigned char* iv, unsigned char* salt, unsigned salt_len) {

}
