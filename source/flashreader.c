#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <errno.h>

#include <mbedtls/aes.h>
#include <mbedtls/md.h>

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

    if (handle->filesize != NAND_SIZE_SPARE && handle->filesize != (NAND_SIZE_SPARE + sizeof(KeysBin))) {
        puts_err("This doesn't seem like a NAND backup");
        Nand_Close(handle);
        return -EINVAL;
    }

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

    if (handle->superblock != NULL) {
        free(handle->superblock);
        handle->superblock = NULL;
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
        debug_printf(1, "ecc_read: %02X%02X%02X%02X\n", ecc_read[i][0], ecc_read[i][1], ecc_read[i][2], ecc_read[i][3]);
        debug_printf(1, "ecc_calc: %02X%02X%02X%02X\n", ecc_calc[0],    ecc_calc[1],    ecc_calc[2],    ecc_calc[3]   );
        ret = -12;

        continue;
    }

    return ret;
}

int Nand_ReadPages(NandHandle* handle, unsigned page, unsigned count, unsigned char *data, bool spare) {
    my_assert(handle != NULL && handle->fp != NULL && data != NULL);

    my_assert(page + count <= NAND_PAGE_COUNT);

    fseek(handle->fp, page * NAND_PAGE_SPARE, SEEK_SET);

    unsigned char (*buffer)[NAND_PAGE_SPARE] = calloc(count, NAND_PAGE_SPARE);
    my_assert(buffer != NULL);

    size_t read = fread(buffer, NAND_PAGE_SPARE, count, handle->fp);
    if (read != count) {
        int _errno = errno;
        debug_printf(0, "fread() failure, errno=%i (%s)", _errno, strerror(_errno));
        free(buffer);
        return -1;
    }

    unsigned ss = spare ? NAND_PAGE_SPARE : NAND_PAGE_SIZE;
    for (unsigned i = 0; i < count; i++) {
        int ret = check_page(buffer[i]);
        if (ret != 0)
            debug_printf(0, "check_page() failed (%i)", ret);

        memcpy(data + (i*ss), buffer[i], ss);
    }

    free(buffer);
    return 0;
}

int Nand_ReadClusters(NandHandle* handle, unsigned start, unsigned count, int flags, unsigned char* iv, unsigned char* salt, unsigned salt_len, unsigned char* data) {
    // Validate arguments
    my_assert(handle != NULL && handle->fp != NULL && data != NULL);
    my_assert((flags & 3) == 0 || handle->has_keys);

    // Bounds check
    my_assert(start + count <= SFFS_FAT_MAX);

    int ret = 0;
    unsigned char (*buffer)[NAND_PAGE_SPARE] = calloc(SFFS_PAGES_PER_CLUSTER, NAND_PAGE_SPARE);
    my_assert(buffer != NULL);

    mbedtls_aes_context  aes;
    mbedtls_md_context_t ctx;
    unsigned char iv_buffer[0x10];
    unsigned char hmac_buffer[0x40];
    unsigned char hmac_digest[0x14];

    if (flags & 1) {
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, handle->nandfs_aes_key, 128);
        memcpy(iv_buffer, iv, sizeof iv_buffer);
    }

    if (flags & 2) {
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), true);
        mbedtls_md_hmac_starts(&ctx, handle->nandfs_hmac_key, sizeof handle->nandfs_hmac_key);
        mbedtls_md_hmac_update(&ctx, salt, salt_len);
    }

    for (unsigned i = 0; i < count; i++) {
        if (flags & 1)
            memcpy(iv_buffer, iv, sizeof iv_buffer);

        int ret = Nand_ReadPages(handle, (start + i) * SFFS_PAGES_PER_CLUSTER, SFFS_PAGES_PER_CLUSTER, *buffer, true);
        if (ret != 0)
            break;

        for (int j = 0; j < SFFS_PAGES_PER_CLUSTER; j++) {
            unsigned char* out = data + (((i * SFFS_PAGES_PER_CLUSTER) + j) * NAND_PAGE_SIZE);

            if (flags & 1)
                mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, NAND_PAGE_SIZE, iv_buffer, buffer[j], out);
            else
                memcpy(out, buffer[j], NAND_PAGE_SIZE);

            if (flags & 2)
                mbedtls_md_hmac_update(&ctx, out, NAND_PAGE_SIZE);
        }
    }


    if (flags & 2) {
        for (unsigned i = (sizeof hmac_buffer / NAND_HMAC_SIZE); i; i--) {
            // Last cluster is sitting in buffer.
            memcpy(hmac_buffer + sizeof hmac_buffer - (i * NAND_HMAC_SIZE), buffer[SFFS_PAGES_PER_CLUSTER - i] + NAND_PAGE_SIZE + 1, NAND_HMAC_SIZE);
        }

        mbedtls_md_hmac_finish(&ctx, hmac_digest);

        if (memcmp(hmac_digest, hmac_buffer + 0, sizeof hmac_digest) != 0) {
            debug_printf(2, "HMAC #0 mismatch");
            if (memcmp(hmac_digest, hmac_buffer + 0x14, sizeof hmac_digest != 0)) {
                ret = -116;
                debug_printf(2, "HMAC #1 mismatch")
                debug_printf(0, "HMAC verification failed");
                if (memcmp(hmac_buffer + 0, hmac_buffer + 0x14, sizeof hmac_digest) != 0) {
                    debug_printf(0, "HMAC #0 and #1 do not match each other");
                    ret = -114;
                }
            }
        }
    }

    free(buffer);
    return ret;
}

int Nand_PickSuperblock(NandHandle* handle) {
    my_assert(handle != NULL && handle->fp != NULL && handle->has_keys);

    int        ret;
    SFFSFatEnt cluster = SFFS_FAT_RSVD_HI;
    unsigned   count   = SFFS_SUPERBLOCK_SIZE / SFFS_CLUSTER_SIZE;
    int        superblock_idx = 0x10;
    uint32_t   superblock_iter = 0;

    SFFSSuperblock* superblock = malloc(SFFS_SUPERBLOCK_SIZE);
    my_assert(superblock != NULL);

    for (int i = 0; i < 0x10; i++) {
        // Peek the start of the superblock.
        ret = Nand_ReadPages(handle, (cluster + (i * count)) * SFFS_PAGES_PER_CLUSTER, 1, superblock->data, false);
        if (ret != 0) {
            debug_printf(2, "Peek superblock #%i failed (%i)", i, ret);
            continue;
        }

        if (superblock->header.magic != SFFS_MAGIC) { // endian-symmetrical
            debug_printf(2, "Superblock #%i does not seem to have a superblock", i);
            continue;
        }

        if (be32toh(superblock->header.iteration) > superblock_iter) {
            superblock_idx = i;
            superblock_iter = be32toh(superblock->header.iteration);
            debug_printf(3, "Superblock #%i is looking cool (iter=%#010x)", i, superblock_iter);
        }
    }

    if (superblock_idx == 0x10) {
        debug_printf(0, "Filesystem not found");
        free(superblock);
        return -104;
    }

    debug_printf(3, "Chosen superblock: %i (iter=%#010x)", superblock_idx, superblock_iter);

    cluster += (superblock_idx * count);
    SFFSSaltData salt = { .cluster = htobe32(cluster) };
    ret = Nand_ReadClusters(handle, cluster, count, 2, 0, salt.data, sizeof salt.data, superblock->data);
    if (ret == 0) {
        handle->superblock = superblock;
    } else {
        debug_printf(0, "Read superblock failed (%i)", ret);
        free(superblock);
    }

    return ret;
}
