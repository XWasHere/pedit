# pedit 
# Copyright (C) 2021 xwashere
# This program is free software: you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by 
# the Free Software Foundation, either version 3 of the License, or 
# (at your option) any later version. 
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
# GNU General Public License for more details. 
# You should have received a copy of the GNU General Public License 
# along with this program.  If not, see <https://www.gnu.org/licenses/>. 


.PHONY: build clean

build: src/main.c src/vmem.c src/vmem.h
	mkdir --parent build
	gcc -w -c src/main.c -o build/main.o
	gcc -w -c src/vmem.c -o build/vmem.o
	gcc build/main.o build/vmem.o -o pedit

clean:
	rm -f build/*.o
	rm -f pedit
	rm -f pedit.exe
