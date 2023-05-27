# install Python and related dependencies
echo "=================================================================="
echo "                installing Python & dependencies"
echo "=================================================================="
cd ..
DIR=$(pwd)
echo "Current directory is: "$DIR
sudo apt-get install python3.7 -y
sudo apt-get install python3-pip -y
python3.7 -m pip install --upgrade pip
python3.7 -m pip install --user numpy
python3.7 -m pip install --user scipy
python3.7 -m pip install --user networkx
python3.7 -m pip install --user matplotlib
python3.7 -m pip install --user plotly
sudo apt install python3.7-dev -y
# install Dyninst
echo "=================================================================="
echo "                    installing Dyninst"
echo "=================================================================="
echo "Current directory is: "$(pwd)
sudo apt  install cmake -y
sudo apt-get install zlib1g-dev -y
sudo apt-get install m4 -y
wget https://github.com/dyninst/dyninst/archive/v10.1.0.tar.gz
tar -xzvf v10.1.0.tar.gz
rm -rf prefix
mkdir prefix
cd prefix
cmake $DIR/dyninst-10.1.0 -DCMAKE_INSTALL_PREFIX=$DIR/prefix
make install -j32
cd ..
echo "export DYNINST_LIB=$DIR/prefix/lib" >> $DIR/.bashrc
echo "export DYNINST_INCLUDE=$DIR/prefix/include" >> $DIR/.bashrc
echo "export DYNINSTAPI_RT_LIB=$DIR/prefix/lib/libdyninstAPI_RT.so" >> $DIR/.bashrc
echo "export LD_LIBRARY_PATH=$DIR/prefix/lib" >> $DIR/.bashrc
source $DIR/.bashrc 
# set up boost
echo "=================================================================="
echo "                    installing Boost"
echo "=================================================================="
echo "Current directory is: "$(pwd)
wget https://boostorg.jfrog.io/artifactory/main/release/1.66.0/source/boost_1_66_0.tar.gz
rm -rf boost_1_66_0
tar -zxvf boost_1_66_0.tar.gz 
cd boost_1_66_0/
./bootstrap.sh --prefix=/usr/ 
./b2 
sudo ./b2 install 
cd ..
cat /usr/include/boost/version.hpp
# install GDB
echo "=================================================================="
echo "                    installing GDB"
echo "=================================================================="
echo "Current directory is: "$(pwd)
sudo apt-get install texinfo -y
sudo apt-get install python2.7-dev -y
wget https://ftp.gnu.org/gnu/gdb/gdb-10.1.tar.gz
rm -rf gdb-10.1
tar -xvzf gdb-10.1.tar.gz
cd gdb-10.1
./configure
make -j12 
cd ..
gdb --version
# install RR
echo "=================================================================="
echo "                    installing RR"
echo "=================================================================="
echo "Current directory is: "$(pwd)
wget https://github.com/rr-debugger/rr/releases/download/5.4.0/rr-5.4.0-Linux-$(uname -m).deb
sudo dpkg -i rr-5.4.0-Linux-$(uname -m).deb
sudo apt-get install python3-apt
sudo sh -c 'echo 1 >/proc/sys/kernel/perf_event_paranoid'
# install PIN
echo "=================================================================="
echo "                    installing PIN"
echo "=================================================================="
echo "Current directory is: "$(pwd)
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.11-97998-g7ecce2dac-gcc-linux.tar.gz
tar -zxvf pin-3.11-97998-g7ecce2dac-gcc-linux.tar.gz
mv pin-3.11-97998-g7ecce2dac-gcc-linux pin-3.11
echo "=================================================================="
echo "                    installing git-lfs"
echo "=================================================================="
echo "Current directory is: "$(pwd)
sudo apt-get install git-lfs -y
