#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
char * analyze_elf(const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        perror("Error opening file");
        return NULL;
    }
    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
        fprintf(stderr, "Failed to read ELF header.\n");
        fclose(f);
        return NULL;
    }

    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || 
        ehdr.e_ident[EI_MAG1] != ELFMAG1 || 
        ehdr.e_ident[EI_MAG2] != ELFMAG2 || 
        ehdr.e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "File is not a valid ELF.\n");
        fclose(f);
        return NULL;
    }

    printf("--- ELF Dependency Analysis ---\n");
    printf("Architecture: %s-bit\n", (ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? "64" : "32"));




    fclose(f);
    return ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? "64" : "32";
}

static inline size_t pad4(size_t x) { return (x + 3) & ~((size_t)3); }

char *bid_elf32(char * filepath) {
   
char *bid = (char*)malloc(0x40);
    const char *path = filepath;
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    /* Read ELF header */
    Elf32_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
        fprintf(stderr, "Failed to read ELF header: %s\n", strerror(errno));
        fclose(f);
        return NULL;
    }

    /* Basic checks */
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        fclose(f);
        return NULL;
    }
    if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "Non-little-endian ELF not supported by this tool (EI_DATA=%u)\n",
                (unsigned)ehdr.e_ident[EI_DATA]);
        fclose(f);
        return NULL;
    }

    /* Read program headers */
    if (ehdr.e_phoff == 0 || ehdr.e_phnum == 0) {
        fprintf(stderr, "No program headers present\n");
        fclose(f);
        return NULL;
    }

    if (fseek(f, (long)ehdr.e_phoff, SEEK_SET) != 0) {
        perror("fseek e_phoff");
        fclose(f);
        return NULL;
    }

    Elf32_Phdr *phdrs = calloc(ehdr.e_phnum, sizeof(Elf32_Phdr));
    if (!phdrs) {
        perror("calloc");
        fclose(f);
        return NULL;
    }

    if (fread(phdrs, sizeof(Elf32_Phdr), ehdr.e_phnum, f) != ehdr.e_phnum) {
        fprintf(stderr, "Failed to read program headers\n");
        free(phdrs);
        fclose(f);
        return NULL;
    }

    int found = 0;
    for (int i = 0; i < ehdr.e_phnum; ++i) {
        Elf32_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_NOTE) continue;
        if (ph->p_filesz == 0) continue;

        /* read note segment into buffer */
        uint8_t *seg = malloc(ph->p_filesz);
        if (!seg) {
            perror("malloc note segment");
            break;
        }
        if (fseek(f, (long)ph->p_offset, SEEK_SET) != 0) {
            perror("fseek note offset");
            free(seg);
            break;
        }
        if (fread(seg, 1, ph->p_filesz, f) != ph->p_filesz) {
            fprintf(stderr, "Failed to read note segment\n");
            free(seg);
            break;
        }

        /* iterate notes */
        size_t off = 0;
        while (off + sizeof(Elf32_Nhdr) <= (size_t)ph->p_filesz) {
            Elf32_Nhdr nh;
            memcpy(&nh, seg + off, sizeof(nh));
            off += sizeof(Elf32_Nhdr);

            if (off + pad4(nh.n_namesz) + pad4(nh.n_descsz) > (size_t)ph->p_filesz) {
                /* malformed note, stop scanning this segment */
                break;
            }

            const char *name = (const char *)(seg + off);
            size_t namesz = nh.n_namesz;
            off += pad4(namesz);

            const uint8_t *desc = seg + off;
            size_t descsz = nh.n_descsz;
            off += pad4(descsz);

            /* Check for GNU build-id: name == "GNU" and type == NT_GNU_BUILD_ID (3) */
            if (namesz >= 4 && memcmp(name, "GNU", 3) == 0 && nh.n_type == NT_GNU_BUILD_ID) {
                /* print build-id as hex */

                size_t b=0;
                for ( b= 0; b < descsz; ++b) {
                    snprintf(bid+b*2,sizeof(bid),"%02x", desc[b]);
                }
                bid[b*2]='\0';
                found = 1;
            }
        }

        free(seg);
        if (found) break; /* stop after finding first build-id */
    }

    free(phdrs);
    fclose(f);

    if (!found) {
        fprintf(stderr, "GNU build-id not found in %s\n", path);
        return NULL;
    }

    return bid;
}


char *get_buildid(const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) { perror("fopen"); return NULL; }
    char bid[100];
    // Read ELF header
    Elf64_Ehdr ehdr;
    fread(&ehdr, 1, sizeof(ehdr), f);

    // Read section headers
    fseek(f, ehdr.e_shoff, SEEK_SET);
    Elf64_Shdr shdr;
    // Read section header string table index
    uint16_t shstrndx = ehdr.e_shstrndx;

    // Read section header string table offset
    fseek(f, ehdr.e_shoff + shstrndx * sizeof(shdr), SEEK_SET);
    fread(&shdr, 1, sizeof(shdr), f);
    char *shstrtab = malloc(shdr.sh_size);
    fseek(f, shdr.sh_offset, SEEK_SET);
    fread(shstrtab, 1, shdr.sh_size, f);

    // Iterate all sections to find .note.gnu.build-id
    for (int i = 0; i < ehdr.e_shnum; i++) {
        fseek(f, ehdr.e_shoff + i * sizeof(shdr), SEEK_SET);
        fread(&shdr, 1, sizeof(shdr), f);

        if (shdr.sh_type == SHT_NOTE) {
            const char *sec_name = shstrtab + shdr.sh_name;
            if (strcmp(sec_name, ".note.gnu.build-id") == 0) {
                unsigned char *data = malloc(shdr.sh_size);
                fseek(f, shdr.sh_offset, SEEK_SET);
                fread(data, 1, shdr.sh_size, f);

                uint32_t namesz = *(uint32_t*)(data);
                uint32_t descsz = *(uint32_t*)(data + 4);
                uint32_t type   = *(uint32_t*)(data + 8);

                unsigned char *desc = data + 12 + ((namesz + 3) & ~3);

                // allocate memory for hex string
                char *bid = malloc(descsz * 2 + 1);
                if (!bid) return NULL;

                for (uint32_t j = 0; j < descsz; j++) {
                    sprintf(bid + j*2, "%02x", desc[j]); 
                }
                bid[descsz*2] = '\0';  

                return bid;
                free(data);
                break;
            }
        }

    }

    free(shstrtab);
    fclose(f);
    return NULL;
}


char * check_Ident(char *filepath) {
    char *arch = analyze_elf(filepath);
    char *bid;
    printf("arch : %s\n",arch);
    if (arch == "64")
    bid = get_buildid(filepath);
else
    bid = bid_elf32(filepath);

    return bid;
}