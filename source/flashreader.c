#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <errno.h>

#include <mbedtls/aes.h>
#include <mbedtls/md.h>

#include "flashreader.h"

static SFFSSaltData _Nand_GetSalt(NandHandle* handle, unsigned inode, uint32_t i);
static unsigned char* _Nand_GetSaltIV(SFFSSaltData* salt, unsigned char out[0x10]);

int Nand_Init(NandHandle* handle, const char* filepath) {
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
    fseek(handle->fp, 0, SEEK_SET);

    if (handle->filesize == (NAND_SIZE_SPARE + sizeof(KeysBin))) {
        fseek(handle->fp, NAND_SIZE_SPARE, SEEK_SET);
        fread(&handle->keys, sizeof(KeysBin), 1, handle->fp);
        handle->has_keys = true;
    } else if (handle->filesize != NAND_SIZE_SPARE) {
        debug_printf(0, "This doesn't seem like a NAND backup");
        Nand_Close(handle);
        return -EINVAL;
    }

    return 0;
}

int Nand_ImportKeys(NandHandle* handle, const char* keys_filepath) {
    if (!handle || !keys_filepath)
        return -EINVAL;

    FILE* fp = fopen(keys_filepath, "rb");
    if (!fp) {
        int _errno = errno;
        debug_printf(0, "%s: %s", keys_filepath, strerror(_errno));
        return -_errno;
    }

    fread(&handle->keys, sizeof(KeysBin), 1, fp);
    fclose(fp);
    handle->has_keys = true;
    return 0;
}

void Nand_Close(NandHandle* handle) {
    if (!handle)
        return;

    if (handle->fp != NULL)
        fclose(handle->fp);

    free(handle->superblock);

    memset(handle, 0, sizeof *handle);
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
    unsigned char *spare = page + NAND_PAGE_SIZE;

    if (spare[0] != 0xFF)
        return -13;

    int ret = 0;
    for (int i = 0; i < 4; i++) {
        unsigned char (*ecc_data)[0x200] = (unsigned char (*)[0x200])page;
        unsigned char (*ecc_read)[4] = (unsigned char (*)[4])(spare + NAND_SPARE_SIZE - 0x10);
        unsigned char   ecc_calc[4];

        calc_ecc(ecc_data[i], ecc_calc);
        if (memcmp(ecc_read[i], ecc_calc, sizeof ecc_calc) == 0) // Good
            continue;

        if (memcmp(ecc_read[i], (unsigned char[4]){0xFF, 0xFF, 0xFF, 0xFF}, sizeof ecc_read[i]) == 0) { // Erased
            continue;
        }

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

    if (fs && (!handle->superblock && Nand_PickSuperblock(handle) != 0)) {
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

    if (start + count > SFFS_FAT_MAX) {
        debug_printf(0, "cluster is out of bounds (%#x+%#x > %#x)", start, count, SFFS_FAT_MAX);
        return -EINVAL;
    }

    int ret = 0;
    unsigned char (*buffer)[NAND_PAGE_SPARE] = calloc(SFFS_PAGES_PER_CLUSTER, NAND_PAGE_SPARE);
    my_assert(buffer != NULL);

    mbedtls_aes_context  aes;
    mbedtls_md_context_t ctx;
    unsigned char iv_buffer[0x10];
    unsigned char hmac_buffer[0x40] = {};
    unsigned char hmac_digest[0x14];

    if (flags & 1) {
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_dec(&aes, (const unsigned char *)handle->keys.otp.nandfs_key, 128);
        memcpy(iv_buffer, iv, sizeof iv_buffer);
    }

    if (flags & 2) {
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), true);
        mbedtls_md_hmac_starts(&ctx, (const unsigned char *)handle->keys.otp.nandfs_hmac_key, sizeof handle->keys.otp.nandfs_hmac_key);
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

            int n_hmac = (sizeof hmac_buffer / NAND_HMAC_SIZE);
            int k = SFFS_PAGES_PER_CLUSTER - j;
            if (k <= n_hmac)
                memcpy(hmac_buffer + sizeof hmac_buffer - (k * NAND_HMAC_SIZE), buffer[j] + NAND_PAGE_SIZE + 1, NAND_HMAC_SIZE);
        }
    }


    if (flags & 2) {
        // hexdump("HMAC buffer", hmac_buffer, sizeof hmac_buffer);

        mbedtls_md_hmac_finish(&ctx, hmac_digest);
        if (memcmp(hmac_digest, hmac_buffer + 0, sizeof hmac_digest) != 0) {
            debug_printf(2, "HMAC #0 mismatch");
            if (memcmp(hmac_digest, hmac_buffer + 0x14, sizeof hmac_digest) != 0) {
                debug_printf(2, "HMAC #1 mismatch")
                if (memcmp(hmac_buffer + 0, hmac_buffer + 0x14, sizeof hmac_digest) != 0) {
                    debug_printf(0, "HMAC #0 and #1 do not match each other");
                    ret = -114;
                } else {
                    debug_printf(0, "HMAC verification failed");
                    ret = -116;
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

        debug_printf(3, "Superblock %i: iter=%08x, generation=%08x", i, be32toh(superblock->header.iteration), be32toh(superblock->header.generation));
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

int Nand_StatFilesystem(NandHandle* handle, NandFSStats* out) {
    if (!_Nand_ValidHandle(handle, true))
        return -EINVAL;

    SFFSSuperblock* superblock = handle->superblock;
    NandFSStats st = {};

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
                debug_printf(2, "Filesystem insanity: cluster %#06x points to itself", i);
            } else if (x < SFFS_FAT_RSVD_LO) {
                debug_printf(2, "Filesystem insanity: cluster %#06x points down to the boot region (%#06x < %#06x)", i, x, SFFS_FAT_RSVD_LO);
            } else if (x >= SFFS_FAT_RSVD_HI) {
                debug_printf(2, "Cluster %#06x points into the metadata area? (%#06x >= %#06x)", i, x, SFFS_FAT_RSVD_HI);
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
            case SFFS_FST_TYPE_FILE:
                total_files_size += be32toh(entry->filesize);
            case SFFS_FST_TYPE_DIR:
                st.used_inodes++;
                break;

            default:
                debug_printf(2, "Filesystem insanity: inode %#06x has invalid mode %#04x. who signed this superblock?", i, entry->mode);
                break;
        }
    }

    debug_printf(1, "Filesystem stats:  iteration=%08x, generation=%08x", be32toh(superblock->header.iteration), be32toh(superblock->header.generation));
    debug_printf(1, "Free clusters:     %#06x (%u)", st.free_clusters, st.free_clusters);
    debug_printf(1, "Used clusters:     %#06x (%u)", st.used_clusters, st.used_clusters);
    debug_printf(1, "Bad clusters:      %#06x (%u)", st.bad_clusters, st.bad_clusters);
    debug_printf(1, "Reserved clusters: %#06x (%u)", st.reserved_clusters, st.reserved_clusters);
    debug_printf(1, "\"Erased\" clusters: %#06x (%u)", st.erased_clusters, st.erased_clusters);
    debug_printf(1, "Free inodes:       %#06x (%u)", st.free_inodes, st.free_inodes);
    debug_printf(1, "Used inodes:       %#06x (%u)", st.used_inodes, st.used_inodes);
    debug_printf(1, "Total files size:  %uKiB (%#x)", total_files_size >> 10, total_files_size);
    unsigned overhead = (st.used_clusters * st.cluster_size) - total_files_size;
    debug_printf(1, "Cluster overhead:  %uKiB (%#x)", overhead >> 10, overhead);

    if (out)
        *out = st;

    return 0;
}

int Nand_FindInode(NandHandle* handle, unsigned inode, const char* path) {
    if (!_Nand_ValidHandle(handle, true) || !path)
        return SFFS_FST_EOF; // return -EINVAL;

    int nlen = strlen(path);

    SFFSFstEnt* fst = handle->superblock->fst;
    int x = 0;
    while (path[x] && x < nlen) {
        const char* ptr = path + x;
        SFFSFstEnt* entry = &fst[inode];

        int ilen = strcspn(ptr, "/");
        if (ilen > SFFS_FST_MAXNAMELEN) {
            debug_printf(0, "Item '%.*s' in /%s is too long", ilen, ptr, path);
            return SFFS_FST_EOF; // return -101;
        }

        if ((entry->mode & SFFS_FST_TYPE_MASK) != SFFS_FST_TYPE_DIR) {
            debug_printf(0, "Trying to look for item '%.*s' in a file /%.*s", ilen, ptr, x - 1, path);
            return SFFS_FST_EOF;
        }

        for (inode = be16toh(entry->child); inode != SFFS_FST_EOF; inode = be16toh(fst[inode].sibling)) {
            if (inode >= SFFS_FST_MAX) {
                debug_printf(1, "Invalid inode# %#06x in directory. who signed this superblock?", inode);
                return SFFS_FST_EOF; // return -103;
            }

            if (strnlen(fst[inode].filename, SFFS_FST_MAXNAMELEN) == ilen && memcmp(fst[inode].filename, ptr, ilen) == 0)
                break;
        }

        if (inode == SFFS_FST_EOF) {
            debug_printf(0, "Could not find '%.*s' under /%.*s", ilen, ptr, x, path);
            break;
        }

        x += ilen + 1;
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

int Nand_StatInode(NandHandle* handle, unsigned inode, NandFileStat* st) {
   if (!_Nand_ValidHandle(handle, true) || !st)
        return -EINVAL;

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
        debug_printf(1, "Inode %u has been deleted", inode);
        return -106;
    }

    memset(st, 0, sizeof *st);
    strncpy(st->name, entry->filename, SFFS_FST_MAXNAMELEN);
    st->inode    = inode;
    st->type     = entry->mode & SFFS_FST_TYPE_MASK;
    st->mode     = entry->mode >> 2;
    st->uid      = be32toh(entry->uid);
    st->gid      = be16toh(entry->gid);
    st->filesize = be32toh(entry->filesize);

    return 0;
}

int Nand_OpenFileInode(NandHandle* handle, unsigned inode, NandFile* fp) {
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
        debug_printf(1, "Inode %u has been deleted", inode);
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
    for (SFFSFatEnt fat = be16toh(entry->sclust); i < fp->nclust && fat != SFFS_FAT_EOF; fat = be16toh(handle->superblock->fat[fat]), i++) {
        if (fat < SFFS_FAT_RSVD_LO || fat >= SFFS_FAT_MAX) {
            debug_printf(0, "Invalid cluster entry in chain (%#x) for file '%.*s'. who signed this superblock?", fat, SFFS_FST_MAXNAMELEN, entry->filename);
            return -103;
        }

        fp->cltbl[i] = fat;
        // debug_printf(3, "cluster index %u, entry value %#06x", i, fat);
    }

    if (i != fp->nclust) {
        debug_printf(1, "cluster chain too short? (fsize=%#x, nclust=%u, i=%u)", fp->fsize, fp->nclust, i);
        return -103;
    }

    SFFSFatEnt lclust = be16toh(handle->superblock->fat[fp->nclust]);
    if (lclust < SFFS_FAT_EOF) {
        debug_printf(2, "cluster chain too long? (fsize=%#x, nclust=%u, i=%u %04hX)", fp->fsize, fp->nclust, i, lclust);
    }

    fp->inode         = inode;
    fp->buffer        = malloc(SFFS_CLUSTER_SIZE);
    fp->buffer_offset = -1;

    my_assert(fp->buffer != NULL);

    return 0;
}

int Nand_OpenFile(NandHandle* handle, const char* path, NandFile* fp) {
    return Nand_OpenFileInode(handle, Nand_FindPath(handle, path), fp);
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

int Nand_ReadFileA(NandHandle* handle, NandFile* fp, unsigned offset, unsigned char* data, unsigned len) {
    if (!_Nand_ValidHandle(handle, true) || !fp)
        return -EINVAL;

    int ret = fp->ret;
    if (ret != 0)
        return ret;

    unsigned progress = 0;
    if (offset + len > fp->fsize)
        len = fp->fsize - offset;

    while (len) {
        if (fp->buffer_offset != -1 && (offset & -SFFS_CLUSTER_SIZE) == fp->buffer_offset) {
            unsigned read = SFFS_CLUSTER_SIZE;
            if ((progress + read) > len)
                read = len - progress;

            memcpy(data + progress, fp->buffer + offset - fp->buffer_offset, read);
            progress += read;
            offset += read;
            len -= read;
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

int Nand_ReadFile(NandHandle* handle, NandFile* fp, unsigned char* data, unsigned len) {
    if (!_Nand_ValidHandle(handle, true) || !fp)
        return -EINVAL;

    int ret = fp->ret;
    if (ret == 0) {
        ret = Nand_ReadFileA(handle, fp, fp->fpos, data, len);
        if (ret >= 0)
            fp->fpos += ret;
    }

    return ret;
}

int Nand_SeekFile(NandHandle* handle, NandFile* fp, int where, int whence) {
    if (!_Nand_ValidHandle(handle, true) || !fp)
        return -EINVAL;

    int start;
    switch (whence) {
        case SEEK_SET:
            start = 0;
            break;

        case SEEK_CUR:
            start = fp->fpos;
            break;

        case SEEK_END:
            start = fp->fsize;
            break;

        default:
            return -101;
    }

    start += where;
    if (start > fp->fsize)
        return -101;

    fp->fpos = start;
    return 0;
}

int Nand_OpenDirInode(NandHandle* handle, unsigned inode, NandDirectory* dirp) {
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
        debug_printf(1, "Inode %u has been deleted", inode);
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

int Nand_OpenDir(NandHandle* handle, const char* dirpath, NandDirectory* dirp) {
    return Nand_OpenDirInode(handle, Nand_FindPath(handle, dirpath), dirp);
}

NandDirEnt* Nand_ReadDir(NandHandle* handle, NandDirectory* dirp, NandDirEnt* pent) {
    if (!_Nand_ValidHandle(handle, true) || !dirp)
        return NULL;

    if (dirp->cur == SFFS_FST_EOF)
        return NULL;

    if (!pent)
        pent = &dirp->buf;

    if (Nand_StatInode(handle, dirp->cur, pent) == 0) {
        dirp->cur = be16toh(handle->superblock->fst[dirp->cur].sibling);
        return pent;
    }

    return NULL;
}

void Nand_RewindDir(NandHandle* handle, NandDirectory* dirp) {
    if (!_Nand_ValidHandle(handle, true) || !dirp)
        return;

    dirp->cur = be16toh(handle->superblock->fst[dirp->inode].child);
}
