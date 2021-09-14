# DYNINST_INCLUDE and DYNINST_LIB should be set to locations
# where Dyniinst header and library files were installed, respectively
#CXX=cl
CXX=g++
CC=gcc
all: count_node preprocess

count_node: count_node.o cJSON.o
	$(CXX) count_node.o cJSON.o -L$(DYNINST_LIB) -lboost_system -ltbbmalloc_proxy -lcommon -lstdc++ -lm\
	       	-o count_node -std=c++11
count_node.o: count_node.cpp
	$(CXX) -g -c $(CFLAGS) -I$(DYNINST_INCLUDE) count_node.cpp -std=c++11


preprocess: preprocess.o cJSON.o
	$(CXX) preprocess.o cJSON.o -L$(DYNINST_LIB) -lboost_system -ltbbmalloc_proxy -lcommon -lstdc++ -lm\
	       	-o preprocess -std=c++11
preprocess.o: preprocess.cpp
	$(CXX) -g -c $(CFLAGS) -I$(DYNINST_INCLUDE) preprocess.cpp -std=c++11
#preprocess: preprocess.o cJSON.o
#	$(CXX) preprocess.o cJSON.o -L$(DYNINST_LIB) -ldyninstAPI -lboost_system -ltbbmalloc_proxy -linstructionAPI -lparseAPI -lsymtabAPI -lcommon -lstdc++ -lm\
#	      -shared -Wl,-soname,static_preprocess.so -o static_preprocess.so -std=c++11
#
#preprocess.o: preprocess.cpp
#	$(CXX) -g -c -fPIC $(CFLAGS) -I$(DYNINST_INCLUDE) preprocess.cpp -std=c++11

cJSON.o: cJSON.c
	$(CC) -g -c -fPIC $(CFLAGS) cJSON.c #-std=c++11

clean:
	rm cJSON.o preprocess.o preprocess count_node.o count_node

#clean:
#	rm static_preprocess.so
