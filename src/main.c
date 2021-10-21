/*
    pedit
    Copyright (C) 2021 xwashere

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

#include "vmem.h"

#define readuint32(addr) ((((uint8_t*)addr)[0]) | (((uint32_t)((uint8_t*)addr)[1]) << 8) | (((uint8_t*)(addr))[2] << 16) | (((uint8_t*)(addr))[3] << 24))
#define readuint16(addr) ((((uint8_t*)addr)[0]) | (((uint8_t*)addr)[1] << 8))

#define u3264union(name) union { uint32_t name##32; uint64_t name##64; };

struct datadir {
    uint32_t virt_address;
    uint32_t size;
};

struct sectionheader {
    char name[9];
    uint32_t virtual_size;
    uint32_t virtual_addr;
    uint32_t raw_data_size;
    uint32_t raw_data;
    uint32_t relocs;
    uint32_t linenos;
    uint16_t reloc_count;
    uint16_t lineno_count;
    uint32_t flags;
};

struct export_directory_table {
    uint32_t flags;
    uint32_t timestamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name_rva;
    uint32_t ordinal_base;
    uint32_t entry_count;
    uint32_t name_count;
    uint32_t export_address_table;
    uint32_t name_pointer_table;
    uint32_t ordinal_table;
};

struct import {
    int   isordinal;
    char* name;
    int   ordinal;
};

struct imported_dll {
    char*          name;
    int            import_count;
    struct import* symbols;
};

struct import_table {
    int dll_count;
    struct imported_dll* dlls;
};

struct pe {
    uint16_t machine;
    uint16_t section_count;
    uint16_t optional_header_size;
    uint16_t characteristics;
    uint16_t optheader_magic;
    uint8_t  linker_major;
    uint8_t  linker_minor;
    uint32_t code_size;
    uint32_t initialized_data_size;
    uint32_t uninitialized_data_size;
    uint32_t entry_point;
    uint32_t code_base;
    uint32_t data_base;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t os_major;
    uint16_t os_minor;
    uint16_t image_major;
    uint16_t image_minor;
    uint16_t subsystem_major;
    uint16_t subsystem_minor;
    uint32_t image_size;
    uint32_t headers_size;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dllcharacteristics;
    uint64_t stack_reserve_size;
    uint64_t stack_commit_size;
    uint64_t heap_reserve_size;
    uint64_t heap_commit_size;
    uint32_t loader_flags;
    uint32_t directory_count;
    struct export_directory_table export_directory_table;
    struct import_table           import_table;
    struct datadir resource_table;
    struct datadir exception_table;
    struct datadir certificate_table;
    struct datadir reloc_table;
    struct datadir debug_table;
    struct datadir arch_table;
    struct datadir global_table;
    struct datadir tls_table;
    struct datadir loadcfg_table;
    struct datadir boundimport_table;
    struct datadir iat_table;
    struct datadir delay_import_desc;
    struct datadir clr_runtime_header;
    struct datadir reserved_table;
    struct sectionheader* sections;
};

struct pedit_import {
    char*    name;
    uint32_t safe_name_len;
    void*    raddr;
};

struct pedit_dll {
    char*                name;
    uint32_t             import_count;
    struct pedit_import* imports;
};

struct pedit {
    uint32_t          dll_count;
    struct pedit_dll* import_dlls;
};

int main(int argc, char** argv) {
    int f = open(argv[1], O_RDONLY | O_BINARY);
    
    uint8_t* data = malloc(0x1000);
    int   dlen = 0;


    while (1) {
        int r = read(f, data + dlen, 0x1000);
        if (r <= 0) break;
        dlen += r;
        data = realloc(data, dlen + 0x1000);
    }

    struct pedit editor;

    editor.dll_count   = 0;
    editor.import_dlls = malloc(sizeof(struct pedit_dll));
    
    struct pe target;

    uint32_t sigoffset = readuint16(data+0x3c);
    uint32_t hoffset   = sigoffset + 4;
    uint32_t ooffset   = hoffset   + 20;
    uint32_t doffset;
    uint32_t soffset;

    memcpy(&target.machine, data + hoffset, 2);
    memcpy(&target.section_count, data + hoffset + 2, 2);
    memcpy(&target.optional_header_size, data + hoffset + 16, 2);
    memcpy(&target.characteristics, data + hoffset + 18, 2);
    
    target.optheader_magic = readuint16(data + ooffset);

    if (target.optheader_magic == 0x010b) {
        
    } else if (target.optheader_magic = 0x020b) {
        target.image_base      = ((uint64_t)readuint32(data + ooffset + 24) | (uint64_t)readuint32(data + ooffset + 28) >> 32);
        target.directory_count = readuint32(data + ooffset + 108);

        doffset = ooffset + 112;
        soffset = doffset + target.directory_count * 8;

        target.sections = malloc(sizeof(struct sectionheader) * target.section_count);

        struct vmem* mem = vmem_init();

        for (int i = 0; i < target.section_count; i++) {
            memset(target.sections[i].name, 0, 9);
            memcpy(target.sections[i].name, data + soffset + i * 40, 8);
            
            target.sections[i].virtual_size = readuint32(data + soffset + (i * 40) + 8);
            target.sections[i].virtual_addr = readuint32(data + soffset + (i * 40) + 12);
            target.sections[i].raw_data_size= readuint32(data + soffset + (i * 40) + 16);
            target.sections[i].raw_data     = readuint32(data + soffset + (i * 40) + 20);

            vmem_add_page(mem, target.sections[i].virtual_addr, target.sections[i].virtual_addr + target.sections[i].virtual_size, target.sections[i].raw_data);
        }

        for (int i = 0; i < target.directory_count; i++) {
            uint32_t addr = readuint32(data + doffset + (i * 8));
            uint32_t len = readuint32(data + doffset + (i * 8) + 4);
            if (len > 0) {
                addr = vmem_addr(mem, addr);
                if (i == 0) {

                } else if (i == 1) {
                    int o = 0;
                    while (1) {
                        editor.import_dlls[editor.dll_count].imports = malloc(sizeof(struct pedit_dll));
                        editor.import_dlls[editor.dll_count].import_count = 0;
                        
                        struct pedit_dll* dll = &editor.import_dlls[editor.dll_count];

                        uint32_t lt = readuint32(data + addr + o * 20);
                        uint32_t tm = readuint32(data + addr + o * 20 + 4);
                        uint32_t fw = readuint32(data + addr + o * 20 + 8);
                        uint32_t nm = readuint32(data + addr + o * 20 + 12);
                        uint32_t at = readuint32(data + addr + o * 20 + 16);

                        char*    name = (uint32_t)vmem_addr(mem, nm) + data;

                        dll->name = name;

                        if (lt == 0) break;

                        int e = 0;
                        uint64_t* entries = (uint32_t)vmem_addr(mem, lt) + data;

                        for (int ii = 0; entries[ii] != 0; ii++) {
                            if (entries[ii] & 0x8000000000000000) {

                            } else {
                                uint32_t nte    = entries[ii] & 0x8FFFFFFF;
                                uint16_t hint   = (uint32_t)vmem_addr(mem, nte) + data;
                                char*    target = (uint32_t)vmem_addr(mem, nte) + data + 2;
                                dll->imports[dll->import_count].name = target;
                                dll->imports[dll->import_count].safe_name_len = strlen(target);
                                dll->imports[dll->import_count].raddr = (uint32_t)vmem_addr(mem, nte) + data;
                                dll->import_count++;
                                dll->imports = realloc(dll->imports, sizeof(struct pedit_import) * (dll->import_count + 1));
                            }
                        }

                        editor.dll_count++;
                        editor.import_dlls = realloc(editor.import_dlls, sizeof(struct pedit_dll) * (editor.dll_count + 1));
                        o++;
                    }
                } else if (i == 2) {

                } else if (i == 3) {

                } else if (i == 4) {

                } else if (i == 5) {

                } else if (i == 6) {

                } else if (i == 7) {

                } else if (i == 8) {
                    
                } else if (i == 9) {

                } else if (i == 10) {

                } else if (i == 11) {
                    
                } else if (i == 12) {

                } else if (i == 13) {

                } else if (i == 14) {

                } else if (i == 15) {

                }
            }
        }
    }

    struct termios old;
    struct termios term;

    tcgetattr(0,    &term);
    tcgetattr(0,    &old );
    cfmakeraw(      &term);
    tcsetattr(0, 0, &term);

    int state = 0;
    int line  = 0;

    int current_dll = 0;
    int editing     = 0;
    int dmode       = 0;
    int cpos        = 0;
    char* buf       = malloc(65);
    int buflen      = 0;

    char** items = 0;
    int    itemc = 0;

    goto display;

    while (1) {
        char c = getchar();

        if (c == 0x1b) {
            if (dmode == 0) {
                char cc = getchar();
                if (cc == '[') {
                    char ccc = getchar();
                    if (ccc == 'A') {
                        if (line != 0) line--;
                        goto display;
                    } else if (ccc == 'B') {
                        if (line != itemc - 1) line++;
                        goto display;
                    }
                }
            } else if (dmode == 1) {
                char cc = getchar();
                if (cc == '[') {
                    char ccc = getchar();
                    if (ccc == 'C') {
                        cpos++;
                        goto display;
                    } else if (ccc == 'D') {
                        cpos--;
                        goto display;
                    }
                }
            }
        }

        if (c == 13) {
            if (dmode == 0) {
                if (state == 0) {
                    if (line == 0) {
                        state = 1;
                        line = 0;
                    } else if (line == 1) {
                        break;
                    }
                } else if (state == 1) {
                    if (line == editor.dll_count) {
                        state = 0;
                        line = 0;
                    } else {
                        current_dll = line;
                        state = 2;
                    }
                } else if (state == 2) {
                    if (line == editor.import_dlls[current_dll].import_count) {
                        state = 1;
                        line = current_dll;
                    } else {
                        editing = line;
                        memset(buf, 0, 64);
                        strcpy(buf, editor.import_dlls[current_dll].imports[editing].name);
                        dmode = 1;
                        cpos = strlen(buf);
                    }
                }
            } else if (dmode == 1) {
                if (state == 1) {
                    dmode = 0;
                    strcpy(editor.import_dlls[editing].name, buf);
                } else if (state == 2) {
                    dmode = 0;
                    strcpy(editor.import_dlls[current_dll].imports[editing].name, buf);
                }
            }
            goto display;
        }

        if (c == 3) break;
        
        if (c == 127) {
            if (dmode == 0) {
                if (state == 2) {
                    for (int i = line; i < editor.import_dlls[current_dll].import_count - 1; i++) {
                        memmove(editor.import_dlls[current_dll].imports[i].raddr, editor.import_dlls[current_dll].imports[i+1].raddr, 20);
                        editor.import_dlls[current_dll].imports[i] = editor.import_dlls[current_dll].imports[i+1];
                    }
                    editor.import_dlls[current_dll].import_count--;
                }
            } else if (dmode == 1) {
                int len = strlen(buf);
                char* tmp = malloc(len);
                strcpy(tmp, buf + cpos);
                strcpy(buf + cpos - 1, tmp);
                cpos--;
                goto display;
            }
        }

        if (dmode == 0) {
            if (state == 1) {
                if (c == 'r') {
                    editing = line;
                    memset(buf, 0, 64);
                    strcpy(buf, editor.import_dlls[line].name);
                    dmode = 1;
                    cpos = strlen(buf);
                }
            }
        } else if (dmode == 1) {
            int len = strlen(buf);
            char* tmp = malloc(len);
            strcpy(tmp, buf + cpos);
            strcpy(buf + cpos + 1, tmp);
            buf[cpos] = c;
            cpos++;
        }

        display:;
#define ADD_ITEM(text) \
items[itemc] = malloc(strlen(text) + 1); \
memset(items[itemc], 0, strlen(text) + 1); \
strcpy(items[itemc], text); \
itemc++; \
items = realloc(items, sizeof(char*) * (itemc + 1));

        printf("\x1b[2J");
        items = malloc(sizeof(char*));
        itemc = 0;

        if (dmode == 0) {
            if (state == 0) {
                ADD_ITEM("Imports");
                ADD_ITEM("Quit");
            } else if (state == 1) {
                for (int i = 0; i < editor.dll_count; i++) {
                    ADD_ITEM(editor.import_dlls[i].name);
                }
                ADD_ITEM("Back");
            } else if (state == 2) {
                for (int i = 0; i < editor.import_dlls[current_dll].import_count; i++) {
                    ADD_ITEM(editor.import_dlls[current_dll].imports[i].name);
                }
                ADD_ITEM("Back");
            }

            for (int i = 0; i < itemc; i++) {
                printf("\x1b[%i;2H|%c %s\n", 
                    i + 1, 
                    (line == i) ? '>' : ' ', 
                    items[i]);
            }
        } else if (dmode == 1) {
            printf("\x1b[%i;2H|> %s\x1b[%i;%iH\n",
                line + 1, 
                buf, 
                line, 
                cpos + 5);
        }
    }

    tcsetattr(0, 0, &old);

    int output = open("./a.exe", O_WRONLY | O_CREAT | O_BINARY);
    write(output, data, dlen);
    close(output);
}
