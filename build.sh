set -xe
clang main.c crypto.c -o main -Wall -Wextra -lcrypto -lssl
