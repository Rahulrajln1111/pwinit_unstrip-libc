#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>

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

    fseek(f, ehdr.e_phoff, SEEK_SET);

    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (fread(&phdr, 1, sizeof(phdr), f) != sizeof(phdr)) {
            fprintf(stderr, "Failed to read Program Header.\n");
            break;
        }

        if (phdr.p_type == PT_INTERP) {
            char linker_path[256];
            long current_pos = ftell(f);
            
            fseek(f, phdr.p_offset, SEEK_SET);
            
            if (fgets(linker_path, sizeof(linker_path), f) != NULL) {
                printf("Required Dynamic Linker (ld): %s\n", linker_path);
            } else {
                printf("Required Dynamic Linker (ld): Read error\n");
            }

            fseek(f, current_pos, SEEK_SET);
            break;
        }
    }


    fclose(f);
    return ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? "64" : "32";
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
    return arch;
}