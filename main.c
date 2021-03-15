// Created by Reverier from L-team, 2021.02.24

// flag:  acf23b4e-764c-4a58-af1c-54073ac8ebea

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static jmp_buf len_jmp;
static jmp_buf incoming;

static int magic[] = {9,  11, 6,  90, 91, 10, 84, 5,  77, 87, 86, 84,
                      11, 77, 84, 9,  85, 64, 77, 9,  6,  89, 11, 77,
                      85, 84, 88, 87, 91, 9,  11, 64, 5,  10, 5,  9};

// libc version, for rizzo.
static const char* libcs = "GNU C Library (GNU libc) release release version 2.33.\nCopyright (C) 2021 Free Software Foundation, Inc.\nThis is free software; see the source for copying conditions.\nThere is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A\nPARTICULAR PURPOSE.\nCompiled by GNU CC version 10.2.0.\nlibc ABIs: UNIQUE IFUNC ABSOLUTE\nFor bug reporting instructions, please see:\n<https://bugs.archlinux.org/>.";

static const char* glibcs = "core/glibc 2.33-4";

void check_len_real(char* v1) {
    int i = strlen(v1);
    if (i != 36) {
        longjmp(len_jmp, i);
    } else {
        for (i = 0; i < 36; i++) {
            v1[i] ^= 0x57;
        }
        longjmp(len_jmp, 36);
    }
}

int check_len(char* v1) {
    int n = setjmp(len_jmp);
    if (!n) {
        check_len_real(v1);
    } else if (n != 36) {
        return 0;
    } else {
        return 1;
    }
}

void real_valid(int i, int n) {
    if (magic[i] != n) {
        longjmp(incoming, 1);
    } else
        return;
}

void valid(char* buf, int n) {
    for (size_t i = 0; i < n; i++) {
        real_valid(i, (buf[i]+4)^0x33);
    }
    longjmp(incoming, 2);
}

int main() {
    char buf[200];

    printf("<<- Welcome to AntCTF & D3CTF! ->>\n\nInput your key: ");
    scanf("%200s", buf);

    if (!check_len(buf)) {
        printf("Sorry.\n\n");
        exit(0);
    }
    int n = setjmp(incoming);
    if (!n) {
        valid(buf, 36);
    } else if (n == 1) {
        printf("Sorry.\n\n");
        exit(0);
    } else {
        printf("Good!\n\n");
        exit(0);
    }

    return 0;
}
