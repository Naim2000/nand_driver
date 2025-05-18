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

static SFFSSaltData _Nand_GetSalt(NandHandle* handle, unsigned inode, uint32_t i);
static unsigned char* _Nand_GetSaltIV(SFFSSaltData* salt, unsigned char out[0x10]);

int Nand_Init(NandHandle* handle, const char* filepath, const char* keys_filepath) {
    if (!handle || !filepath)
        return -EINVAL;

    memset(handle, 0, sizeof *handle);

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
        debug_printf(0, "This doesn't seem like a NAND backup");
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
    if (!handle)
        return;

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

static bool _Nand_ValidHandle(NandHandle* handle, bool fs) {
    if (!handle) {
        debug_printf(0, "handle is NULL");
        return false;
    }

    if (!handle->fp) {
        debug_printf(0, "handle does not have an associated file");
        return false;
    }

    if (fs && !handle->superblock && Nand_PickSuperblock(handle) != 0) {
        debug_printf(0, "Failed to initialize filesystem");
        return false;
    }

    return true;
}

int Nand_ReadPages(NandHandle* handle, unsigned page, unsigned count, unsigned char *data, bool spare) {
    if (!_Nand_ValidHandle(handle, false) || !data)
        return -EINVAL;

    if (page + count > NAND_PAGE_COUNT) {
        debug_printf(0, "page is out of bounds (%#x+%#x > %#x)", page, count, NAND_PAGE_COUNT);
        return -EINVAL;
    }

    fseek(handle->fp, page * NAND_PAGE_SPARE, SEEK_SET);

    unsigned char (*buffer)[NAND_PAGE_SPARE];
    unsigned char *data_ptr = NULL;
    if (!spare) {
        my_assert((buffer = calloc(count, NAND_PAGE_SPARE)) != NULL);
        data_ptr = *buffer;
    } else {
        data_ptr = data;
    }
    size_t read = fread(data_ptr, NAND_PAGE_SPARE, count, handle->fp);
    if (read != count) {
        int _errno = errno;
        debug_printf(0, "fread failure, errno=%i (%s)", _errno, strerror(_errno));
        free(buffer);
        return -1;
    }

    for (unsigned i = 0; i < count; i++) {
        int ret = check_page(data_ptr + (i * NAND_PAGE_SPARE));
        if (ret != 0)
            debug_printf(0, "check_page failed (%i)", ret);

        if (!spare)
            memcpy(data + (i * NAND_PAGE_SIZE), buffer[i], NAND_PAGE_SIZE);
    }


    free(buffer);
    return 0;
}

int Nand_ReadClusters(NandHandle* handle, unsigned start, unsigned count, int flags, const unsigned char* iv, const unsigned char* salt, unsigned salt_len, unsigned char* data) {
    // Validate arguments
    if (!_Nand_ValidHandle(handle, false) || !data)
        return -EINVAL;

    if ((flags & 3) && !handle->has_keys) {
        debug_printf(0, "can't do this without the NAND keys");
        return -EINVAL;
    }

    if(start + count > SFFS_FAT_MAX) {
        debug_printf(0, "cluster is out of bounds (%#x+%#x > %#x)", start, count, SFFS_FAT_MAX);
        return -EINVAL;
    }

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
        // hexdump("HMAC buffer", hmac_buffer, sizeof hmac_buffer);

        mbedtls_md_hmac_finish(&ctx, hmac_digest);

        if (memcmp(hmac_digest, hmac_buffer + 0, sizeof hmac_digest) != 0) {
            debug_printf(2, "HMAC #0 mismatch");
            if (memcmp(hmac_digest, hmac_buffer + 0x14, sizeof hmac_digest) != 0) {
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
    if (!_Nand_ValidHandle(handle, false))
        return -EINVAL;

    if (!handle->has_keys) {
        debug_printf(0, "can't do this without NAND keys");
        return -EINVAL;
    }

    int        ret;
    SFFSFatEnt cluster = SFFS_FAT_RSVD_HI;
    unsigned   count   = SFFS_SUPERBLOCK_SIZE / SFFS_CLUSTER_SIZE;
    int        superblock_idx = 0x10;
    uint32_t   superblock_iter = 0;

    SFFSSuperblock* superblock = handle->superblock ?: malloc(SFFS_SUPERBLOCK_SIZE);
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
        }
    }

    if (superblock_idx == 0x10) {
        debug_printf(0, "Filesystem not found");
        free(superblock);
        handle->superblock = NULL;
        return -104;
    }

    debug_printf(3, "Chosen superblock: %i (iter=%#010x)", superblock_idx, superblock_iter);

    cluster += (superblock_idx * count);
    SFFSSaltData salt = _Nand_GetSalt(handle, SFFS_FST_EOF, cluster);
    ret = Nand_ReadClusters(handle, cluster, count, 2, 0, salt.data, sizeof salt.data, superblock->data);
    if (ret == 0) {
        handle->superblock = superblock;
    } else {
        handle->superblock = NULL;
        free(superblock);
        debug_printf(0, "Read superblock failed (%i)", ret);
    }

    return ret;
}

int Nand_StatFilesystem(NandHandle* handle, SFFSStats* out) {
    if (!_Nand_ValidHandle(handle, true))
        return -EINVAL;

    SFFSSuperblock* superblock = handle->superblock;
    SFFSStats st = {};

    // Clusters
    st.cluster_size = SFFS_CLUSTER_SIZE;

    for (SFFSFatEnt i = SFFS_FAT_RSVD_LO; i < SFFS_FAT_RSVD_HI; i++) {
        SFFSFatEnt x = be16toh(superblock->fat[i]);

        if (x == SFFS_FAT_FREE) {
            st.free_clusters++;
        } else if (x == SFFS_FAT_ERASED) {
            // debug_printf(3, "cluster %#06x is \"erased\"", i);
            st.erased_clusters++;
        } else if (x == SFFS_FAT_BAD) {
            st.bad_clusters++;
        } else if (x == SFFS_FAT_RESERVED) {
            st.reserved_clusters++;
        } else if (x == SFFS_FAT_EOF) {
            st.used_clusters++;
        } else {
            st.used_clusters++;
            if (x == i) {
                debug_printf(0, "Filesystem insanity: cluster %#06x points to itself", i);
            } else if (x < SFFS_FAT_RSVD_LO) {
                debug_printf(0, "Filesystem insanity: cluster %#06x points down to the boot region (%#06x < %#06x)", i, x, SFFS_FAT_RSVD_LO);
            } else if (x >= SFFS_FAT_RSVD_HI) {
                debug_printf(0, "Cluster %#06x points into the metadata area? (%#06x >= %#06x)", i, x, SFFS_FAT_RSVD_HI);
            }
        }
    }

    // Inodes
    unsigned total_files_size = 0;

    for (int i = 0; i < SFFS_FST_MAX; i++) {
        SFFSFstEnt* entry = &superblock->fst[i];

        switch (entry->mode & SFFS_FST_TYPE_MASK) {
            case SFFS_FST_TYPE_FREE:
                st.free_inodes++;
                break;

            default:
                debug_printf(0, "Filesystem insanity: inode %#06x has invalid mode %#04x", i, entry->mode);
                break;
            case SFFS_FST_TYPE_FILE:
                total_files_size += be32toh(entry->filesize);
            case SFFS_FST_TYPE_DIR:
                st.used_inodes++;
                break;


        }
    }

    debug_printf(2, "Filesystem stats: iteration=%08x, generation=%08x", be32toh(superblock->header.iteration), be32toh(superblock->header.generation));
    debug_printf(2, "Free clusters:     %#06x (%u)", st.free_clusters, st.free_clusters);
    debug_printf(2, "Used clusters:     %#06x (%u)", st.used_clusters, st.used_clusters);
    debug_printf(2, "Bad clusters:      %#06x (%u)", st.bad_clusters, st.bad_clusters);
    debug_printf(2, "Reserved clusters: %#06x (%u)", st.reserved_clusters, st.reserved_clusters);
    debug_printf(2, "\"Erased\" clusters: %#06x (%u)", st.erased_clusters, st.erased_clusters);
    debug_printf(2, "Free inodes:       %#06x (%u)", st.free_inodes, st.free_inodes);
    debug_printf(2, "Used inodes:       %#06x (%u)", st.used_inodes, st.used_inodes);
    debug_printf(2, "Total files size:  %uKiB (%#x)", total_files_size >> 10, total_files_size);
    unsigned overhead = (st.used_clusters * st.cluster_size) - total_files_size;
    debug_printf(2, "Cluster overhead:  %uKiB (%#x)", overhead >> 10, overhead);

    if (out)
        *out = st;

    return 0;
}

int Nand_FindInode(NandHandle* handle, unsigned inode, const char* path) {
    if (!_Nand_ValidHandle(handle, true) || !path)
        return SFFS_FST_EOF; // return -EINVAL;

    int nlen = strlen(path);

    SFFSFstEnt* fst = handle->superblock->fst;
    const char* ptr = path;
    while (*ptr && ptr - path < nlen) {
        SFFSFstEnt* entry = &fst[inode];

        int ilen = strcspn(ptr, "/");
        if (ilen > SFFS_FST_MAXNAMELEN) {
            debug_printf(2, "Item '%.*s' in /%s is too long", ilen, ptr, path);
            return SFFS_FST_EOF; // return -101;
        }

        if ((entry->mode & SFFS_FST_TYPE_MASK) != SFFS_FST_TYPE_DIR) {
            debug_printf(2, "Trying to look for item '%.*s' in a file /%.*s", ilen, ptr, (int)(ptr - path - 1), path);
            return SFFS_FST_EOF;
        }

        for (inode = be16toh(entry->child); inode != SFFS_FST_EOF; inode = be16toh(fst[inode].sibling)) {
            if (inode >= SFFS_FST_MAX) {
                debug_printf(0, "Invalid inode# %#06x in directory. who signed this superblock?", inode);
                return SFFS_FST_EOF; // return -103;
            }

            if (strnlen(fst[inode].filename, SFFS_FST_MAXNAMELEN) == ilen && memcmp(fst[inode].filename, ptr, ilen) == 0)
                break;
        }

        if (inode == SFFS_FST_EOF) {
            debug_printf(2, "Could not find '%.*s' under /%.*s", ilen, ptr, (int)(ptr - path), path);
            break;
        }

        ptr += ilen + 1;
    }

    return inode;
}

int Nand_FindPath(NandHandle* handle, const char* path) {
    if (!_Nand_ValidHandle(handle, true) || !path)
        return SFFS_FST_EOF; // return -EINVAL;

    if (*path == '\0') // root
        return 0x0;

    else if (*path != '/') {
        debug_printf(0, "IOS/FS would not get a message for path '%s'", path);
        return SFFS_FST_EOF; // return -101;
    }

    else if (strnlen(path, SFFS_FST_MAXPATHLEN + 1) == SFFS_FST_MAXPATHLEN + 1) {
        debug_printf(0, "Path '%s' is too long", path);
        return SFFS_FST_EOF;
    }

    return Nand_FindInode(handle, 0x0, path + 1);
}

int Nand_OpenInode(NandHandle* handle, unsigned inode, NandFile* fp) {
    if (!_Nand_ValidHandle(handle, true) || !fp)
        return -EINVAL;

    memset(fp, 0x0, sizeof *fp);

    if (inode == SFFS_FST_EOF) {
        debug_printf(0, "Trying to open nothing");
        return -106;
    }

    if (inode >= SFFS_FST_MAX) {
        debug_printf(0, "Inode %#x is out of bounds (>=%#x)", inode, SFFS_FST_MAX);
        return -101;
    }

    SFFSFstEnt* entry = &handle->superblock->fst[inode];
    if ((entry->mode & SFFS_FST_TYPE_MASK) == SFFS_FST_TYPE_FREE) {
        debug_printf(1, "File '%.*s has been deleted", SFFS_FST_MAXNAMELEN, entry->filename);
        return -106;
    }

    else if ((entry->mode & SFFS_FST_TYPE_MASK) == SFFS_FST_TYPE_DIR) {
        debug_printf(0, "Trying to open a directory '%.*s' as a file", SFFS_FST_MAXNAMELEN, entry->filename);
        return -101;
    }

    fp->fsize  = be32toh(entry->filesize);
    fp->nclust = (fp->fsize + SFFS_CLUSTER_SIZE - 1) / SFFS_CLUSTER_SIZE;
    fp->cltbl  = calloc(fp->nclust, sizeof *fp->cltbl);
    my_assert(fp->cltbl != NULL);

    int i = 0;
    for (SFFSFatEnt fat = be16toh(entry->sclust); fat != SFFS_FAT_EOF && i < fp->nclust; fat = be16toh(handle->superblock->fat[fat]), i++) {
        if (fat < SFFS_FAT_RSVD_LO || fat >= SFFS_FAT_MAX) {
            debug_printf(0, "Invalid cluster entry in chain (%#x) for file '%.*s'. who signed this superblock?", fat, SFFS_FST_MAXNAMELEN, entry->filename);
            return -103;
        }

        fp->cltbl[i] = fat;
        // debug_printf(3, "cluster index %u, entry value %#06x", i, fat);
    }

    if (i != fp->nclust) {
        debug_printf(0, "cluster chain too short? (fsize=%#x, nclust=%u, i=%u)", fp->fsize, fp->nclust, i);
        return -103;
    }

    fp->inode         = inode;
    fp->buffer        = malloc(SFFS_CLUSTER_SIZE);
    fp->buffer_offset = -1;

    my_assert(fp->buffer != NULL);

    return 0;
}

void Nand_CloseFile(NandHandle* handle, NandFile* fp) {
    if (fp) {
        free(fp->cltbl);
        free(fp->buffer);
    }
}

static SFFSSaltData _Nand_GetSalt(NandHandle* handle, unsigned inode, uint32_t i) {
    SFFSSaltData salt = {};

    if (inode != SFFS_FST_EOF) {
        SFFSFstEnt* entry = &handle->superblock->fst[inode];

        salt.uid = entry->uid;
        memcpy(salt.filename, entry->filename, SFFS_FST_MAXNAMELEN);
        salt.inode = htobe32(inode);
        salt.generation = entry->generation;
    }

    salt.cluster = htobe32(i);

    return salt;
}

static unsigned char* _Nand_GetSaltIV(SFFSSaltData* salt, unsigned char out[0x10]) {
    if (out && salt) {
        for (int i = 0; i < 0x10; i++)
            for (int j = i; j < 0x40; j += 0x10)
                out[i] = salt->data[j];
    }

    return out;
}

int Nand_ReadFileA(NandHandle* handle, NandFile* fp, unsigned char* data, unsigned offset, unsigned len) {
    if (!_Nand_ValidHandle(handle, true) || !fp)
        return -EINVAL;

    int ret = fp->ret;
    if (ret != 0)
        return ret;

    unsigned left = len;
    unsigned progress = 0;
    if (offset + len > fp->fsize)
        left = fp->fsize - offset;

    while (left) {
        if (fp->buffer_offset != -1 && (offset & -SFFS_CLUSTER_SIZE) == fp->buffer_offset) {
            unsigned read = SFFS_CLUSTER_SIZE;
            if (progress + read > len)
                read = len - progress;

            memcpy(data + progress, fp->buffer + offset - fp->buffer_offset, read);
            progress += read;
            offset += read;
            left -= read;
            continue;
        }

        unsigned cluster_idx = offset / SFFS_CLUSTER_SIZE;
        SFFSSaltData salt = _Nand_GetSalt(handle, fp->inode, cluster_idx);
        unsigned char ivbuffer[0x10];
        ret = Nand_ReadClusters(handle, fp->cltbl[cluster_idx], 1, 3, _Nand_GetSaltIV(&salt, ivbuffer), salt.data, sizeof salt.data, fp->buffer);
        if (ret != 0)
            break;

        fp->buffer_offset = cluster_idx * SFFS_CLUSTER_SIZE;
    }

    return (fp->ret = ret) ?: progress;
}

int Nand_OpenDir(NandHandle* handle, unsigned inode, NandDirectory* dirp) {
    if (!_Nand_ValidHandle(handle, true) || !dirp)
        return -EINVAL;

    memset(dirp, 0, sizeof *dirp);

    if (inode == SFFS_FST_EOF) {
        debug_printf(0, "Trying to open nothing");
        return -106;
    }

    if (inode >= SFFS_FST_MAX) {
        debug_printf(0, "Inode %#x is out of bounds (>=%#x)", inode, SFFS_FST_MAX);
        return -101;
    }

    SFFSFstEnt* entry = &handle->superblock->fst[inode];
    if ((entry->mode & SFFS_FST_TYPE_MASK) == SFFS_FST_TYPE_FREE) {
        debug_printf(1, "File '%.*s has been deleted", SFFS_FST_MAXNAMELEN, entry->filename);
        return -106;
    }

    else if ((entry->mode & SFFS_FST_TYPE_MASK) == SFFS_FST_TYPE_FILE) {
        debug_printf(0, "Trying to open a file '%.*s' as a directory", SFFS_FST_MAXNAMELEN, entry->filename);
        return -101;
    }

    dirp->inode = inode;
    dirp->cur   = be16toh(entry->child);

    return 0;
}

NandDirEnt* Nand_ReadDir(NandHandle* handle, NandDirectory* dirp) {
    if (!_Nand_ValidHandle(handle, true) || !dirp)
        return NULL;

    if (dirp->cur == SFFS_FST_EOF)
        return NULL;

    SFFSFstEnt* entry = &handle->superblock->fst[dirp->cur];
    NandDirEnt* pent = &dirp->buf;

    memset(pent, 0, sizeof *pent);
    strncpy(pent->name, entry->filename, SFFS_FST_MAXNAMELEN);
    pent->inode    = dirp->cur;
    pent->type     = entry->mode & SFFS_FST_TYPE_MASK;
    pent->mode     = entry->mode >> 2;
    pent->uid      = be32toh(entry->uid);
    pent->gid      = be16toh(entry->gid);
    pent->filesize = be32toh(entry->filesize);

    dirp->cur = be16toh(handle->superblock->fst[dirp->cur].sibling);

    return pent;
}

void Nand_RewindDir(NandHandle* handle, NandDirectory* dirp) {
    if (!_Nand_ValidHandle(handle, true) || !dirp)
        return;

    dirp->cur = be16toh(handle->superblock->fst[dirp->inode].child);
}
