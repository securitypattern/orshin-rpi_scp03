This directory contains the code of a slightly modified nano-package library, used to program a master device.

# Client Program testing CoreV Secure element features
## Run on the RaspberryPI

### Compile
cd nano-package-xoodyak/examples/se05x_crypto/linux/
mkdir build && cd build
cmake ../ -DPLUGANDTRUST_SCP03=ON -DPLUGANDTRUST_DEBUG_LOGS=ON
make

### Run test
./ex_se05x_crypto

### Connections

#### Raspberry PI4B I2C Master
Brown: Ground
Yellow: Clock
Green: Data

![photo_5888822577600775535_y](https://github.com/user-attachments/assets/7398445e-445a-473f-8a66-527ac9ef053a)

#### Nexys A7 I2C Slave
![photo_5888822577600775533_y](https://github.com/user-attachments/assets/e4f95626-4e8f-44f8-a949-21a4674eca8f)

#### HS2 Debugger on Nexys A7
!!! The last switch must be in the UP position

![photo_5888822577600775534_y](https://github.com/user-attachments/assets/82b86a3d-a079-4ff5-8c4a-1ccc9f121550)

