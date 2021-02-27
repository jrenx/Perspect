# DYNINST_INCLUDE and DYNINST_LIB should be set to locations
# where Dyniinst header and library files were installed, respectively
#CXX=cl
CXX=g++
CC=gcc
#analysis.o: analysis.cpp
#	$(CXX) -g -c $(CFLAGS) -I$(DYNINST_INCLUDE) analysis.cpp -std=c++11

analysis: analysis.o cJSON.o
	$(CXX) analysis.o cJSON.o -L$(DYNINST_LIB) -ldyninstAPI -lboost_system -ltbbmalloc_proxy -linstructionAPI -lparseAPI -lsymtabAPI -lcommon -lstdc++ -lm\
	       	-o analysis -std=c++11

#analysis: analysis.o
#	$(CXX) analysis.o cJSON.o -L$(DYNINST_LIB) -ldyninstAPI -lboost_system -ltbbmalloc_proxy -linstructionAPI -lparseAPI -lsymtabAPI -lcommon -lstdc++ -lm\
#	      -shared -Wl,-soname,static_analysis.so -o static_analysis.so -std=c++11

analysis.o: analysis.cpp
	$(CXX) -g -c -fPIC $(CFLAGS) -I$(DYNINST_INCLUDE) analysis.cpp -std=c++11

cJSON.o: cJSON.c
	$(CC) -g -c $(CFLAGS) cJSON.c #-std=c++11

clean:
	rm cJSON.o analysis.o analysis


