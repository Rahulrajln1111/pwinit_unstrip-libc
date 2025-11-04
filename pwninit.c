#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include "fieldId.h"
#include <ctype.h>
#include <sys/wait.h>

#define BUF_SIZE 8192
static int run(const char *cmd) {
    FILE *rc = popen(cmd, "r");
if (!rc) {
    perror("popen Failed");
    return 1;  
}
int status = pclose(rc);        
    if (status == -1) {
        perror("pclose");
        return 1;
    }

     // Check exit code
    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code != 0) {
            fprintf(stderr, "Command failed: %s (exit=%d)\n", cmd, exit_code);
        }
        return exit_code;
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "Command killed by signal %d: %s\n", WTERMSIG(status), cmd);
        return 128 + WTERMSIG(status);
    } else {
        fprintf(stderr, "Command ended abnormally: %s\n", cmd);
        return 1;
    }

    return 0;
}
void command_exists(const char *cmd) {
    char check[512];
    snprintf(check, sizeof(check), "which %s >/dev/null 2>&1", cmd);
    int result = system(check);
    if (result) {
        printf("Need to install : '%s'",cmd);
        exit(1);
    }
}
int copy_file(const char *src, const char *dst) {
    FILE *fsrc = fopen(src, "rb");
    if (!fsrc) {
        perror("Error opening source file");
        return 1;
    }

    FILE *fdst = fopen(dst, "wb");
    if (!fdst) {
        perror("Error opening destination file");
        fclose(fsrc);
        return 1;
    }

    char buffer[BUF_SIZE];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), fsrc)) > 0) {
        if (fwrite(buffer, 1, bytes, fdst) != bytes) {
            perror("Write error");
            fclose(fsrc);
            fclose(fdst);
            return 1;
        }
    }

    fclose(fsrc);
    fclose(fdst);
    return 0;
}

static int ensure_executable(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    mode_t m = st.st_mode | S_IXUSR | S_IXGRP | S_IXOTH;
    return chmod(path, m);
}

static int copy_first_match(const char *dir, const char *pattern, const char *dest) {
    char buf[4096];
    snprintf(buf, sizeof(buf), "find %s -type f -name '%s' -print -quit", dir, pattern);
    FILE *f = popen(buf, "r");
    if (!f) return -1;
    if (!fgets(buf, sizeof(buf), f)) { pclose(f); return -1; }
    pclose(f);
   
    char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
    printf("[found] %s\n", buf);
    char src[4096];
    strcpy(src, buf);
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "cp -v \"%s\" \"%s/debug_libc.so\"", src, dest);
    return run(cmd);
}

void trim_inplace(char *s) {
    
    char tmp[100];
    snprintf(tmp,sizeof(tmp),"libc6-dbg%s",s+5);
    int l = strlen(s)+4;
    int i;
    for(i=0;i<l;i++){
        s[i] = tmp[i];
        if(s[i]=='\n')s[i]='\0';
    }

}
 int libc_info(char *buildid, char *out) {
    if (!buildid || !out) return 1;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "curl -s -X POST \"https://libc.rip/api/find\" -H \"Content-Type: application/json\" "
        "-d '{\"buildid\":\"%s\"}' | jq -r '.[0].id'",
        buildid);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen(curl)");
        return 2;
    }
        if (!fgets(out,100, fp)) {
        pclose(fp);
        return 3; 
    }
    pclose(fp);

    trim_inplace(out);
    if (out[0] == '\0') return 4; 

    return 0;
}

void download_dlib(char *ver){


    char cmd[8196];
    char *work = "./libf";
    const char *deb_url1="http://security.ubuntu.com/ubuntu/pool/main/g/glibc";
    const char *deb_url = "https://deb.sipwise.com/debian/pool/main/g/glibc";

   snprintf(cmd,sizeof(cmd),"wget %s/%s.deb",deb_url,ver);
  
   
   FILE *webr = popen(cmd,"r");
   if (webr == NULL) {
        perror("Error running command with popen");
        exit(1);
    
    }
    int status = pclose(webr);        
    if (status == -1) {
        perror("pclose");
        exit(0);
    }
    
}

int extract_debug_from_deb(const char *deblibc,char *bid) {
    mkdir("./tmp",0755);
    chdir("./tmp");
    char cmd[200];
    char arcmd[200];
    snprintf(cmd, sizeof(cmd), "cp ../%s.deb .", deblibc);
    if (run(cmd)) {
        fprintf(stderr, "cp for delicb failed.\n");
        return 1;
        
    }
    snprintf(arcmd, sizeof(arcmd), "ar x '%s.deb'", deblibc);
    FILE *arout = popen(arcmd, "r");
    if (!arout) { perror("popen(ar t)");  
return 1;}

    

    
    snprintf(cmd, sizeof(cmd), "ar x '%s.deb'", deblibc);
    if (run(cmd)) {
        fprintf(stderr, "ar x failed\n");
        return 1;
        
    }

    snprintf(cmd, sizeof(cmd), "tar -xf data.tar*");
    if (run(cmd)) {
        fprintf(stderr, "tar extraction failed\n");
        return 1;
        
    }
    char id2[3];
    id2[0] = bid[0];
    id2[1] = bid[1];
    id2[2] = '\0';
    snprintf(cmd, sizeof(cmd), "cp usr/lib/debug/.build-id/%s/%s.debug ../debuginfo",id2,bid+2);
    if(run(cmd))return 1;
    chdir("..");
    rmdir("./tmp");


    return 0;

}


int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary-path>\n", argv[0]);
        return 2;
    }
    command_exists("wget");
    command_exists("patchelf");
    command_exists("eu-unstrip");

    const char *bin = argv[1];
    const char *deb_url="https://debuginfod.elfutils.org/buildid";

    if (access(bin, F_OK) != 0) {
        fprintf(stderr, "binary %s not found\n", bin);
        return 1;
    }

    const char *work1 = "./debug_patch";
    
    char cmd[8192];
    char *ver;

    mkdir(work1,0755);
    char found[4096] = {0};
    chdir(work1);


    snprintf(cmd, sizeof(cmd), "cp ../libc.* bk.libc.so.6");
    if (run(cmd)) return 1;
    snprintf(cmd, sizeof(cmd), "cp ../ld-* ld-linux.so.2");
    if (run(cmd)) return 1;
    snprintf(cmd, sizeof(cmd), "cp ../%s .",bin);
    if (run(cmd)) return 1;
    char libc[100];
    snprintf(libc, sizeof(libc), "bk.libc.so.6");


    printf("libc filename:%s\n",libc);
    char *arch = check_Ident(libc);
    printf("arch:%s\n",arch);
    if(!strcmp(arch,"64"))arch="amd64";
    else arch="i386";
    sleep(0.5);
    char *bid = get_buildid(libc);
    printf("build-id:%s\n",bid);


    snprintf(cmd, sizeof(cmd), "wget  %s/%s/debuginfo",deb_url,bid);
    if (run(cmd)){
        char dlibc[100];
        printf("[*] Now we are dowloading libc.deb from another source..\n");
        int rs = libc_info(bid,dlibc);
        download_dlib(dlibc);
        if(extract_debug_from_deb(dlibc,bid))return 1;
        printf("[+] debuginfo file of libc.so downloaded Successfully !!\n\n");
    }
    
   
    snprintf(cmd, sizeof(cmd), "cp ./debuginfo ./libc.so.6");
    if (run(cmd)) return 1;

    
    snprintf(cmd, sizeof(cmd), "eu-unstrip bk.libc.so.6 libc.so.6");
    if (run(cmd)) return 1;
    puts("[+] libc has been unstripped Successfully !!\n");

     snprintf(cmd, sizeof(cmd), "patchelf --set-rpath ./ %s",bin);
    if (run(cmd)) return 1;
     snprintf(cmd, sizeof(cmd), "patchelf --set-interpreter ./ld-linux.so.2 ./%s ",bin);
    if (run(cmd)) return 1;

    puts("[+] Binaray patched with debug symbol..");
    ensure_executable("./libc.so.6");

    return 0;
}
