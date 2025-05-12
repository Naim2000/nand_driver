#pragma once

#include <stddef.h>
#include <stdbool.h>
#include "common.h"

typedef int16_t SFFSFatEnt;

enum {
    NAND_PAGE_SIZE  = 0x800, // 2KiB
    NAND_SPARE_SIZE = 0x40,  // 64B
    NAND_HMAC_SIZE  = 0x20,  // 32B
    NAND_PAGE_SPARE = (NAND_PAGE_SIZE + NAND_SPARE_SIZE),

    NAND_BLOCK_SIZE      = 0x20000, // 128KiB
    NAND_PAGES_PER_BLOCK = (NAND_BLOCK_SIZE / NAND_PAGE_SIZE),
    NAND_BLOCK_SPARE     = (NAND_PAGE_SPARE * NAND_PAGES_PER_BLOCK),

    NAND_SIZE            = 0x20000000, // 512MiB
    NAND_BLOCK_COUNT     = (NAND_SIZE / NAND_BLOCK_SIZE),
    NAND_PAGE_COUNT      = (NAND_BLOCK_COUNT * NAND_PAGES_PER_BLOCK),
    NAND_SIZE_SPARE      = (NAND_BLOCK_SPARE * NAND_BLOCK_COUNT),
};

typedef struct SFFSFstEnt {
    char     filename[12];
    uint8_t  owner_perm: 2;
    uint8_t  group_perm: 2;
    uint8_t  other_perm: 2;
    uint8_t  type: 2;
    uint8_t  attributes;
    union {
        SFFSFatEnt sclust;
        uint16_t   child;
    };
    uint16_t sibling;
    uint32_t filesize;
    uint32_t uid;
    uint16_t gid;
    uint32_t generation;
} __attribute__((packed)) SFFSFstEnt;
CHECK_STRUCT_SIZE(SFFSFstEnt, 0x20);

typedef union {
    struct {
        uint32_t uid;
        char     filename[12];
        uint32_t cluster;
        uint32_t fst_pos;
        uint32_t generation;
    } __attribute__((packed));
    uint8_t data[0x40];
} SFFSSaltData;
CHECK_STRUCT_SIZE(SFFSSaltData, 0x40);

typedef struct SFFSSuperblockHeader {
    uint32_t magic;
    uint32_t iteration;
    uint32_t generation;
} SFFSSuperblockHeader;
CHECK_STRUCT_SIZE(SFFSSuperblockHeader, 0xC);

#define SUPERBLOCK_FAT(x) ((SFFSFatEnt *)((uintptr_t)x + sizeof(SFFSSuperblockHeader)))
#define SUPERBLOCK_FST(x) ((SFFSFstEnt *)&SUPERBLOCK_FAT(x)[SFFS_FAT_MAX])

enum {
    SFFS_MAGIC    = 0x53464653, // 'SFFS'

    SFFS_CLUSTER_SIZE = 0x4000, // 16KiB
    SFFS_SUPERBLOCK_SIZE = 0x40000, // 256KiB

    SFFS_PAGES_PER_CLUSTER  = (SFFS_CLUSTER_SIZE / NAND_PAGE_SIZE),
    SFFS_CLUSTERS_PER_BLOCK = (NAND_BLOCK_SIZE / SFFS_CLUSTER_SIZE),

    SFFS_FAT_ERASED   = 0xFFFF, // ?
    SFFS_FAT_FREE     = 0xFFFE,
    SFFS_FAT_BAD      = 0xFFFD,
    SFFS_FAT_RESERVED = 0xFFFC,
    SFFS_FAT_EOF      = 0xFFFB,

    SFFS_FAT_RSVD_LO  = (0x100000 / SFFS_CLUSTER_SIZE),
    SFFS_FAT_RSVD_HI  = ((NAND_SIZE - (SFFS_SUPERBLOCK_SIZE * 16)) / SFFS_CLUSTER_SIZE),
    SFFS_FAT_MAX      = (NAND_SIZE / SFFS_CLUSTER_SIZE),

    SFFS_FST_TYPE_FREE = 0,
    SFFS_FST_TYPE_FILE = 1,
    SFFS_FST_TYPE_DIR  = 2,
    SFFS_FST_EOF       = 0xFFFF,

    SFFS_FST_MAX  = ((SFFSFstEnt *)SFFS_SUPERBLOCK_SIZE - SUPERBLOCK_FST(0x0)),
};

_Static_assert(SFFS_FST_MAX == 0x17FF, "?");

typedef union SFFSSuperblock {
    struct {
        SFFSSuperblockHeader header;
        SFFSFatEnt           fat[SFFS_FAT_MAX];
        SFFSFstEnt           fst[SFFS_FST_MAX];
    };
    uint8_t data[SFFS_SUPERBLOCK_SIZE];
} SFFSSuperblock;

_Static_assert((uintptr_t)SUPERBLOCK_FST(0x0) == 0x1000C, "?");
CHECK_STRUCT_SIZE(SFFSSuperblock, SFFS_SUPERBLOCK_SIZE);

///

enum {
    OTP_WORD_COUNT = 0x20,
};

typedef union {
    struct {
        uint32_t boot1_hash[5];
        uint32_t common_key[4];
        uint32_t device_id;
        union {
            uint8_t device_private_key[30];
            struct {
                uint32_t pad[7];
                uint32_t nandfs_hmac_key[5];
            };
        };
        uint32_t nandfs_key[4];
        uint32_t backup_key[4];
        uint32_t pad2[2];
    };
    uint32_t data[OTP_WORD_COUNT];
} WiiOTP;
CHECK_STRUCT_SIZE(WiiOTP, 0x80);

///

enum {
    SEEPROM_WORD_COUNT = 0x80,
};

#define SEEPROM_COUNTER_STRUCT(name, thestruct...) \
    typedef union { \
        struct __attribute__((packed)) \
            thestruct \
        ; \
        struct { \
            uint16_t sumdata[(sizeof(struct __attribute__((packed)) thestruct)) / 2]; \
            uint16_t checksum; \
        }; \
    } name ;

SEEPROM_COUNTER_STRUCT(Boot2Counter, { uint8_t boot2version, unk1, unk2, padding; uint32_t update_tag; });
SEEPROM_COUNTER_STRUCT(SFFSCounter,  { uint32_t generation; });

typedef union {
    struct __attribute__((packed)) {
        uint32_t     ms_id;
        uint32_t     ca_id;
        uint32_t     ng_key_id;
        uint8_t      ng_signature[2][30];
        Boot2Counter boot2_counters[2];
        SFFSCounter  sffs_counters[3];
        uint8_t      padding[6];
        uint32_t     korean_key[4];
        uint8_t      padding2[116];
        uint16_t     prng_seed[2];
        uint8_t      padding3[4];
    };
    uint16_t data[SEEPROM_WORD_COUNT];
} WiiSEEPROM;

CHECK_STRUCT_SIZE(WiiSEEPROM, 0x100);

///

typedef struct KeysBin {
    char       comment[256];
    WiiOTP     otp;
    char       padding[128];
    WiiSEEPROM seeprom;
    char       padding2[256];
} KeysBin;
CHECK_STRUCT_SIZE(KeysBin, 0x400);

////
