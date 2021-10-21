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

#include "vmem.h"
#include <stdlib.h>

struct vmem* vmem_init() {
    struct vmem* vmem = malloc(sizeof(struct vmem));
    vmem->pages = malloc(sizeof(struct vmem_page));
    vmem->page_count = 0;
    return vmem;
}

void vmem_add_page(struct vmem* vmem, void* start, void* end, void* real) {
    vmem->pages[vmem->page_count].start = start;
    vmem->pages[vmem->page_count].end = end;
    vmem->pages[vmem->page_count].real = real;
    vmem->page_count++;
    vmem->pages = realloc(vmem->pages, sizeof(struct vmem_page) * (vmem->page_count+1));
}

void* vmem_addr(struct vmem* vmem, void* addr) {
    for (int i = 0; i < vmem->page_count; i++) {
        if (addr >= vmem->pages[i].start) {
            if (addr <= vmem->pages[i].end) return addr - vmem->pages[i].start + vmem->pages[i].real;
        }
    }
}
