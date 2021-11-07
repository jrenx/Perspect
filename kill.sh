SDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
pkill python3 -u $USER
pkill para -u $USER
pkill rr -u $USER
pkill gdb -u $USER
pkill get_f -u $USER
pkill get_i -u $USER
rm $DIR/insns_*
rm $DIR/file_lines_
