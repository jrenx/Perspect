# DYNINST_INCLUDE and DYNINST_LIB should be set to locations
# where Dyniinst header and library files were installed, respectively
#CC=cl
#analysis: analysis.o
#	$(CC) analysis.o -L$(DYNINST_LIB) -ldyninstAPI -lboost_system -ltbbmalloc_proxy -linstructionAPI -lparseAPI -lsymtabAPI -lcommon -lstdc++ -lm\
#	       	-o analysis -std=c++11
analysis: analysis.o
	$(CC) analysis.o -L$(DYNINST_LIB) -ldyninstAPI -lboost_system -ltbbmalloc_proxy -linstructionAPI -lparseAPI -lsymtabAPI -lcommon -lstdc++ -lm\
	      -shared -Wl,-soname,static_analysis.so -o static_analysis.so -std=c++11

#analysis.o: analysis.cpp
#	$(CC) -g -c $(CFLAGS) -I$(DYNINST_INCLUDE) analysis.cpp -std=c++11

analysis.o: analysis.cpp
	$(CC) -g -c -fPIC $(CFLAGS) -I$(DYNINST_INCLUDE) analysis.cpp -std=c++11

clean:
	rm analysis.o analysis


