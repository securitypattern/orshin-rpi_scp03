/** @file sm_i2c.c
 *  @brief I2C Interface functions.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ********************** Include files ********************** */
#include "sm_i2c.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <linux/version.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "sm_port.h"

/* ********************** Global variables ********************** */
static char *SE05X_I2C_DEV_NAME = "/dev/i2c-1";
static int SE05x_I2C_DEV = 0;

/* ********************** Defines ********************** */
#define SE05X_I2C_DEV_ADDR 0x62
#define COREV_FIFO_WRITE_DATA_PORT 0x20
#define COREV_STATUS_PORT 0x34
#define COREV_READ_DATA_PORT 0x31
/* ********************** Functions ********************** */

/**
 * Opens the communication channel to I2C device
 */
i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName) {

  unsigned long funcs;
  (void)conn_ctx;

  if (pDevName != NULL) {
    SE05x_I2C_DEV = open(pDevName, O_RDWR);
  } else {
    SE05x_I2C_DEV = open(SE05X_I2C_DEV_NAME, O_RDWR);
  }
  if (SE05x_I2C_DEV < 0) {
    SMLOG_E("I2C: Error in open call \n");
    return I2C_FAILED;
  }

  if (ioctl(SE05x_I2C_DEV, I2C_SLAVE, SE05X_I2C_DEV_ADDR) < 0) {
    SMLOG_E("I2C driver failed setting address\n");
  }

  // clear PEC flag
  if (ioctl(SE05x_I2C_DEV, I2C_PEC, 0) < 0) {
    SMLOG_E("I2C driver: PEC flag clear failed\n");
  }

  // Query functional capacity of I2C driver
  if (ioctl(SE05x_I2C_DEV, I2C_FUNCS, &funcs) < 0) {
    SMLOG_E("Cannot get i2c adapter functionality\n");
    close(SE05x_I2C_DEV);
    return I2C_FAILED;
  } else {
    if (funcs & I2C_FUNC_I2C) {
      SMLOG_E("I2C driver supports plain i2c-level commands.\n");
    } else {
      SMLOG_E("I2C driver CANNOT support plain i2c-level commands!\n");
      close(SE05x_I2C_DEV);
      return I2C_FAILED;
    }
  }
  return I2C_OK;
}

/**
 * Closes the communication channel to I2C device
 */
void axI2CTerm(void *conn_ctx, int mode) {

  (void)conn_ctx;
  (void)mode;
  if (close(SE05x_I2C_DEV) != 0) {
    SMLOG_E("Failed to close i2c device %d.\n", SE05x_I2C_DEV);
  } else {
    SMLOG_I("Close i2c device %d.\n", SE05x_I2C_DEV);
  }

  return;
}

i2c_error_t axI2CWrite(void *conn_ctx, unsigned char bus, unsigned char addr,
                       unsigned char *pTx, unsigned short txLen) {

  int nrWritten = -1;
  i2c_error_t rv;
  (void)conn_ctx;
  (void)bus;
  (void)addr;

  if (pTx == NULL || txLen > MAX_APDU_BUFFER) {
    return I2C_FAILED;
  }

  // TODO: Unefficient!
  unsigned char *data = malloc(txLen + 1);
  data[0] = COREV_FIFO_WRITE_DATA_PORT;
  memcpy(&data[1], pTx, txLen);

  nrWritten = write(SE05x_I2C_DEV, data, txLen + 1);

  if (nrWritten < 0) {
    SMLOG_E("Failed writing data (nrWritten=%d).\n", nrWritten);
    rv = I2C_FAILED;
  } else {
    rv = (nrWritten == (txLen + 1)) ? I2C_OK : I2C_FAILED;
  }

  return rv;
}

i2c_error_t axI2CRead(void *conn_ctx, unsigned char bus, unsigned char addr,
                      unsigned char *pRx, unsigned short rxLen) {
  //SMLOG_D("I2C Read Len: %d\n", rxLen);

  int nrRead = -1;
  i2c_error_t rv;
  (void)conn_ctx;
  (void)bus;
  (void)addr;

  int myBytesread = 0;
  unsigned char myRecBuf[256];

  if (pRx == NULL || rxLen > MAX_APDU_BUFFER) {
    return I2C_FAILED;
  }
  uint8_t status_port[] = {0x34};
  uint8_t data_port[] = {0x31};

  do {
    // Read status if != 0 i have 1 byte to read
    write(SE05x_I2C_DEV, status_port, 1);
    read(SE05x_I2C_DEV, myRecBuf, 1);
    if (myRecBuf[0] != 0) {
      // Read byte from port
      write(SE05x_I2C_DEV, data_port, 1);
      if (read(SE05x_I2C_DEV, myRecBuf, 1) > 0) {
        pRx[myBytesread++] = myRecBuf[0];
        //SMLOG_D("Read from CoreV: 0x%x\n", myRecBuf[0]);
      } else {
        SMLOG_D("Error reading byte from CoreV\n");
        exit(-1);
      }
      if (myBytesread == rxLen) break;
    }
  } while (1);

  return I2C_OK;
}
