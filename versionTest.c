#include "ver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

typedef struct {
    char *ubuntu;      
    char *libc_version; 
} UbuntuGLIBC;

UbuntuGLIBC mapping[] = {
    {"24.04", "2.39"},
    {"23.10", "2.38"},
    {"23.04", "2.37"},
    {"22.04", "2.35"},
    {"20.04", "2.31"},
    {"18.04", "2.27"},
    {"16.04", "2.23"},
    {"14.04", "2.19"},
    {"12.04", "2.15"},
    {"10.04", "2.11.1"}
};
#define MAPPING_COUNT (sizeof(mapping)/sizeof(mapping[0]))

#define BUFSZ 8192


char* get_filename( char *fullpath) {
     char *fname = strrchr(fullpath, '/');  // find last '/'
    if (fname) 
        return fname + 1;  // skip the '/'
    else
        return fullpath;    // no '/' found, return the full string
}

char *run_cmd(const char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;
    size_t cap = BUFSZ;
    char *buf = malloc(cap);
    if (!buf) { pclose(fp); return NULL; }
    buf[0] = '\0';
    size_t len = 0;
    char tmp[512];
    while (fgets(tmp, sizeof(tmp), fp)) {
        size_t tlen = strlen(tmp);
        if (len + tlen + 1 > cap) {
            cap = cap * 2 + tlen;
            char *n = realloc(buf, cap);
            if (!n) { free(buf); pclose(fp); return NULL; }
            buf = n;
        }
        memcpy(buf + len, tmp, tlen);
        len += tlen;
        buf[len] = '\0';
    }
    pclose(fp);
    return buf;
}

char *first_regex_capture(const char *text, const char *pattern, int icase) {
    if (!text) return NULL;
    regex_t re;
    int flags = REG_EXTENDED;
    if (icase) flags |= REG_ICASE;
    if (regcomp(&re, pattern, flags) != 0) return NULL;
    regmatch_t pm[10];
    char *result = NULL;
    if (regexec(&re, text, 10, pm, 0) == 0 && pm[1].rm_so != -1) {
        int start = pm[1].rm_so, end = pm[1].rm_eo;
        int len = end - start;
        result = malloc(len + 1);
        if (result) {
            memcpy(result, text + start, len);
            result[len] = '\0';
        }
    }
    regfree(&re);
    return result;
}

char *libc_for_comment(const char *comment_text) {
    if (!comment_text) return NULL;

    char *found = NULL;

    found = first_regex_capture(comment_text, "~([0-9]{2}\\.[0-9]{1,2})", 1);
    if (!found) {
        
        found = first_regex_capture(comment_text, "Ubuntu[^0-9]*([0-9]{2}\\.[0-9]{1,2})", 1);
    }
    if (!found) {
        found = first_regex_capture(comment_text, "([^0-9]|^)([0-9]{2}\\.[0-9]{1,2})([^0-9]|$)", 1);
       
        if (found) {
            
            free(found);
            found = first_regex_capture(comment_text, "([0-9]{2}\\.[0-9]{1,2})", 1);
        }
    }

    if (!found) return NULL;
     char *result = NULL;
    for (size_t i = 0; i < MAPPING_COUNT; ++i) {
        if (strcmp(found, mapping[i].ubuntu) == 0) {
            result = mapping[i].libc_version;
            break;
        }
    }

    free(found);
    return result;
}

char *detect_highest_glibc(const char *binary) {
    char cmd[1024];
    puts("Checking for Highest compatibility!!");
    snprintf(cmd, sizeof(cmd), "readelf -Ws %s | grep -oE \"GLIBC_[0-9_.]+\"|grep -oE \"[0-9.]+\"|sort -t \".\" -r", binary);
    
    char *output = run_cmd(cmd);
    if (!output) {
        printf("Failed to read symbols or no GLIBC symbols found.\n");
        return NULL;
    }
    char *line = strtok(output,"\n");
return line;
    
}

char *check_version(char *flibc) {
char cmd[1024];
char *fileName = get_filename(flibc);
    if(strncmp(fileName,"bk.libc",7)==0){
        puts("[+] libc* file detected..");

    snprintf(cmd, sizeof(cmd), " strings %s|grep -E \"glibc [0-9]+\.[0-9]+\"|grep -oE \"[0-9]+\.[0-9]+\"|head -1|tr -d '\n'", flibc);
    char *comment = run_cmd(cmd);
    return comment;
    }

    
    snprintf(cmd, sizeof(cmd), "readelf -p .comment %s 2>/dev/null", flibc);
    char *comment = run_cmd(cmd);

    if (!comment || strlen(comment) == 0) {
        fprintf(stderr, "No .comment output (file may be stripped). Try 'strings' fallback.\n");
        if (comment) free(comment);
        
        snprintf(cmd, sizeof(cmd), "strings %s 2>/dev/null", flibc);
        comment = run_cmd(cmd);
        if (!comment || strlen(comment) == 0) {
            fprintf(stderr, "No strings output either. Cannot detect Ubuntu version from comment.\n");
            if (comment) free(comment);
        }
    }

    char *libc = libc_for_comment(comment);
    if (libc) {
        printf("[+] Inferred libc (libc6) version: %s\n", libc);
    }
    else{
        libc = detect_highest_glibc(flibc);
        printf("[+] highest version detected:%s\n",libc);
    }
    free(comment);
    return libc;
}
