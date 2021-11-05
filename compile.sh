SDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
echo "Current dir is: "$SDIR
cd $SDIR"/"binary_analysis && make clean
cd $SDIR"/"binary_analysis && make
cd $SDIR"/"preprocessor && make clean
cd $SDIR"/"preprocessor && make
cd $SDIR"/"pin && make clean
cd $SDIR"/"pin && make PIN_ROOT=/home/renxian2/pin-3.11
