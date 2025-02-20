This directory contains the code of a slightly modified nano-package library, used to program a master device.

Client Program testing CoreV Secure element features
Run on the RaspberryPI

To compile:
cd nano-package-xoodyak/examples/se05x_crypto/linux/
mkdir build && cd build
cmake ../ -DPLUGANDTRUST_SCP03=ON -DPLUGANDTRUST_DEBUG_LOGS=ON
make


./ex_se05x_crypto
