#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>

#include "common.h"
#include "flashreader.h"
#include "structures.h"

static int _cmp_nanddirent(const void* __a, const void* __b) {
    const NandDirEnt *a = __a, *b = __b;

    if (a->type ^ b->type)
        return b->type - a->type;

    return strcmp(a->name, b->name);
}

static const char* _get_modestr(const NandDirEnt* entry, char buffer[8]) {
    if (!entry)
        return NULL;

    memset(buffer, '-', 7);
    if (entry->type == SFFS_FST_TYPE_DIR)
        buffer[0] = 'd';

    for (int i = 0; i < 6; i += 2) {
        unsigned bw = 0x20 >> i, br = bw >> 1;
        if (entry->mode & br)
            buffer[1 + i] = 'r';

        if (entry->mode & bw)
            buffer[2 + i] = 'w';
    }
    buffer[7] = '\0';

    return buffer;
}

static int mkdir_r(const char* _path) {
    for (char* path = strdupa(_path), *ptr = path; (ptr = strchr(ptr, '/')) != NULL; ptr++) {
        debug_printf(3, "mkdir_r path=%s ptr=%s", path, ptr);
        *ptr = 0;
        int rc = mkdir(path, 0774);
        if (rc < 0 && errno != EEXIST) {
            int _errno = errno;
            fprintf(stderr, "mkdir: %s: %s\n", path, strerror(_errno));
            return _errno;
        }
        *ptr = '/';
    }

    return 0;
}

[[noreturn]]
[[gnu::format(printf, 2, 3)]]
void print_usage(int rc, const char* fmt, ...) {
    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vwarnx(fmt, ap);
        va_end(ap);
    }

    fprintf(stderr,
        "usage: %s nand.bin [option]...\n"
        "Options:\n"
        " -H, --help    | Show this prompt\n"
        " -v, --verbose | Increase verbosity level\n"
        " -k, --keys    | Path to keys.bin file for NAND backups without it embedded\n"
        " -s, --stat    | Show filesystem stats\n"
        " -x, --extract | Extract file from NAND\n"
        " -l, --list    | List items in NAND directory\n", program_invocation_short_name);

    exit(rc);
}

static const char* cli_options_short = "-:Hv::k:sx:l:";
static struct option cli_options[] = {
    { "help",    no_argument,       0, 'H' },
    { "verbose", optional_argument, 0, 'v' },
    { "keys",    required_argument, 0, 'k' },
    { "stat",    no_argument,       0, 's' },
    { "extract", required_argument, 0, 'x' },
    { "list",    required_argument, 0, 'l' },
    {},
};


int main(int argc, char* argv[]) {
    int        ret;
    NandHandle nand = {};

    const char* nand_filepath = NULL, *keys_filepath = NULL;
    if (getopt(argc, argv, "-") != 1)
        print_usage(EINVAL, "please provide the path to nand.bin first");

    nand_filepath = optarg;

    while (true) {
        int rc = getopt_long(argc, argv, cli_options_short, cli_options, 0);
        if (rc == -1)
            break;

        switch (rc) {
            case 'k': {
                keys_filepath = optarg;
            } break;

            case 'v': {
                debug_level = optarg ? atoi(optarg) : debug_level + 1;
            } break;

            case 'H': {
                print_usage(0, 0);
            } break;

            // ------------

            case 'x': {
                if (getopt(argc, argv, "-") != 1)
                    print_usage(EINVAL, "extract: missing destination argument");
            } break;

            // ------------

            case 1: { // non-argument
                print_usage(EINVAL, "unrecognized parameter '%s'", optarg);
            } break;

            case '?': {
                print_usage(EINVAL, "unknown option '-%c'", optopt);
            } break;

            case ':': {
                print_usage(EINVAL, "missing argument for '-%c'", optopt);
            } break;
        }
    }

    if (keys_filepath)
        Nand_ImportKeys(&nand, keys_filepath);

    int rc = Nand_Init(&nand, nand_filepath);
    if (rc != 0)
        return rc;

    optind = 2;
    while (true) {
        int rc = getopt_long(argc, argv, cli_options_short, cli_options, 0);
        if (rc == -1)
            break;

        switch (rc) {
            case 's': { // stat
                Nand_StatFilesystem(&nand, 0);
            } break;

            case 'x': { // extract
                const char* srcpath = optarg;
                const char* dstpath = NULL;
                if (getopt(argc, argv, "-") != 1)
                    print_usage(EINVAL, "extract: missing destination argument *");
                dstpath = optarg;

                NandFile fp;
                if (Nand_OpenFile(&nand, srcpath, &fp) != 0 || mkdir_r(dstpath) != 0)
                    break;

                FILE* fpw = fopen(dstpath, "wb");
                if (!fpw) {
                    perror(dstpath);
                    break;
                }

                while ((rc = Nand_ReadFile(&nand, &fp, fp.buffer, SFFS_CLUSTER_SIZE)))
                    fwrite(fp.buffer, rc, 1, fpw);

                fclose(fpw);
                Nand_CloseFile(&nand, &fp);

                if (rc < 0) {
                    printf("%s: read error (%i)\n", srcpath, rc);
                    remove(dstpath);
                    break;
                }
            } break;

            case 'l': { // list
                NandDirectory dirp;
                if (Nand_OpenDir(&nand, optarg, &dirp) != 0)
                    break;

                int n = 0;
                for (NandDirEnt* pent = Nand_ReadDir(&nand, &dirp, NULL); pent != NULL; pent = Nand_ReadDir(&nand, &dirp, NULL), n++)
                    ;

                NandDirEnt* dirlist = calloc(n, sizeof(NandDirEnt));
                Nand_RewindDir(&nand, &dirp);
                for (int i = 0; i < n; i++)
                    Nand_ReadDir(&nand, &dirp, &dirlist[i]);

                qsort(dirlist, n, sizeof(NandDirEnt), _cmp_nanddirent);
                printf("Directory %s, %i items\n", optarg, n);
                printf("%-7s [%-4s %-4s] %-*s\n", "mode", "uid", "gid", SFFS_FST_MAXNAMELEN, "name");

                for (int i = 0; i < n; i++) {
                    char modestr[8];
                    NandDirEnt* pent = &dirlist[i];

                    _get_modestr(pent, modestr);

                    /* `uid` will usually not break the 0x10000 barrier unless files were written from Wii U mode */
                    if (pent->type == SFFS_FST_TYPE_DIR)
                        printf("%s [%04x:%04x] %-*s   dir\n", modestr, pent->uid, pent->gid, SFFS_FST_MAXNAMELEN, pent->name);
                    else if (pent->type == SFFS_FST_TYPE_FILE)
                        printf("%s [%04x:%04x] %-*s   %#x\n", modestr, pent->uid, pent->gid, SFFS_FST_MAXNAMELEN, pent->name, pent->filesize);
                }

                free(dirlist);
            } break;
        }
    }

    Nand_Close(&nand);
    return 0;
}
