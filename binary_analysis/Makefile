# DYNINST_INCLUDE and DYNINST_LIB should be set to locations
# where Dyniinst header and library files were installed, respectively
#CXX=cl
CXX=g++-7
CC=gcc-7

#analysis: analysis.o util.o dataflow_analysis.o static_df_analysis.o stack_analysis.o bitvar_analysis.o cJSON.o
#	$(CXX) analysis.o util.o dataflow_analysis.o static_df_analysis.o stack_analysis.o bitvar_analysis.o cJSON.o -L$(DYNINST_LIB) -ldyninstAPI -lboost_system -ltbbmalloc_proxy -linstructionAPI -lparseAPI -lsymtabAPI -lcommon -lstdc++ -lm\
#	       	-o analysis -std=c++11

#analysis.o: analysis.cpp
#	$(CXX) -g -c $(CFLAGS) -I$(DYNINST_INCLUDE) analysis.cpp -std=c++11

analysis: analysis.o util.o dataflow_analysis.o static_df_analysis.o stack_analysis.o bitvar_analysis.o cJSON.o
	$(CXX) analysis.o util.o dataflow_analysis.o static_df_analysis.o stack_analysis.o bitvar_analysis.o cJSON.o -L$(DYNINST_LIB) -ldyninstAPI -lboost_system -ltbbmalloc_proxy -linstructionAPI -lparseAPI -lsymtabAPI -lcommon -lstdc++ -lm\
	      -shared -Wl,-soname,static_analysis.so -o static_analysis.so -std=c++11 -O2

analysis.o: analysis.cpp
	$(CXX) -g -c -fPIC $(CFLAGS) -I$(DYNINST_INCLUDE) analysis.cpp -std=c++11

util.o: util.cpp
	$(CXX) -g -c -fPIC $(CFLAGS) -I$(DYNINST_INCLUDE) util.cpp -std=c++11

dataflow_analysis.o: dataflow_analysis.cpp
	$(CXX) -g -c -fPIC $(CFLAGS) -I$(DYNINST_INCLUDE) dataflow_analysis.cpp -std=c++11

static_df_analysis.o: static_df_analysis.cpp
	$(CXX) -g -c -fPIC $(CFLAGS) -I$(DYNINST_INCLUDE) static_df_analysis.cpp -std=c++11

stack_analysis.o: stack_analysis.cpp
	$(CXX) -g -c -fPIC $(CFLAGS) -I$(DYNINST_INCLUDE) stack_analysis.cpp -std=c++11

bitvar_analysis.o: bitvar_analysis.cpp
	$(CXX) -g -c -fPIC $(CFLAGS) -I$(DYNINST_INCLUDE) bitvar_analysis.cpp -std=c++11

cJSON.o: cJSON.c
	$(CC) -g -c -fPIC $(CFLAGS) cJSON.c #-std=c++11

#clean:
#	rm cJSON.o analysis.o analysis

clean:
	rm static_analysis.so *.o


