/** @file se05x_scp03.c
 *  @brief Se05x SCP03 implementation.
 *
 * Copyright 2021,2022 NXP
 * SPDX-License-Identifier: Apache-2.0
 * [!] NOTE: Modifications were carried out to the present file with respect to the original one.
 */

/* ********************** Include files ********************** */
#include "sm_port.h"
#include "se05x_types.h"
#include "se05x_tlv.h"
#include "smCom.h"
#include "se05x_scp03_crypto.h"
#include "se05x_scp03.h"
#include <limits.h>
//#include "xoodyak/xoodyak-aead.c"
#include "xoodyak2/Xoodyak.c"
#include "xoodyak2/Xoodyak-full-blocks.c"
#include "xoodyak2/Xoodoo-optimized.c"

/* ********************** Global variables ********************** */

uint8_t se05x_sessionEncKey[AES_KEY_LEN_nBYTE] = {
    0,
};
uint8_t se05x_sessionMacKey[AES_KEY_LEN_nBYTE] = {
    0,
};
uint8_t se05x_sessionRmacKey[AES_KEY_LEN_nBYTE] = {
    0,
};
uint8_t se05x_cCounter[16] = {
    0,
};
uint8_t se05x_mcv[SCP_CMAC_SIZE] = {
    0,
};

uint8_t se05x_staticKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
SE05x_SessionStatus_t se05x_sessionStatus = UNINITIATED;
uint8_t nonceH[16] = {0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00}; /* Keep it constant for now. In reality, it should be randomly generated. */
uint8_t nonceSE[16];
uint8_t counterK[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}; /* Needs to be discussed... */
uint8_t idK[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uint8_t isMACVerified;
uint8_t tag[16];

Xoodyak_Instance instance;

/* ********************** Functions ********************** */

smStatus_t Se05x_API_SCP03_GetSessionKeys(pSe05xSession_t session_ctx,
    uint8_t *encKey,
    size_t *encKey_len,
    uint8_t *macKey,
    size_t *macKey_len,
    uint8_t *rMacKey,
    size_t *rMacKey_len)
{
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(encKey != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(encKey_len != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(macKey != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(macKey_len != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rMacKey != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rMacKey_len != NULL, SM_NOT_OK);

    ENSURE_OR_RETURN_ON_ERROR(*encKey_len >= AES_KEY_LEN_nBYTE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(*macKey_len >= AES_KEY_LEN_nBYTE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(*rMacKey_len >= AES_KEY_LEN_nBYTE, SM_NOT_OK);

    memcpy(encKey, se05x_sessionEncKey, AES_KEY_LEN_nBYTE);
    memcpy(macKey, se05x_sessionMacKey, AES_KEY_LEN_nBYTE);
    memcpy(rMacKey, se05x_sessionRmacKey, AES_KEY_LEN_nBYTE);

    return SM_OK;
}

smStatus_t Se05x_API_SCP03_GetMcvCounter(
    pSe05xSession_t pSessionCtx, uint8_t *pCounter, size_t *pCounterLen, uint8_t *pMcv, size_t *pMcvLen)
{
    ENSURE_OR_RETURN_ON_ERROR(pSessionCtx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pSessionCtx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pCounter != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pCounterLen != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pMcv != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pMcvLen != NULL, SM_NOT_OK);

    ENSURE_OR_RETURN_ON_ERROR(*pCounterLen >= sizeof(se05x_cCounter), SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(*pMcvLen >= sizeof(se05x_mcv), SM_NOT_OK);

    memcpy(pCounter, se05x_cCounter, sizeof(se05x_cCounter));
    memcpy(pMcv, se05x_mcv, sizeof(se05x_mcv));

    return SM_OK;
}

smStatus_t Se05x_API_SCP03_SetSessionKeys(pSe05xSession_t session_ctx,
    const uint8_t *encKey,
    const size_t encKey_len,
    const uint8_t *macKey,
    const size_t macKey_len,
    const uint8_t *rMacKey,
    const size_t rMacKey_len)
{
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(encKey != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(macKey != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rMacKey != NULL, SM_NOT_OK);

    ENSURE_OR_RETURN_ON_ERROR(encKey_len == AES_KEY_LEN_nBYTE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(macKey_len == AES_KEY_LEN_nBYTE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rMacKey_len == AES_KEY_LEN_nBYTE, SM_NOT_OK);

    memcpy(se05x_sessionEncKey, encKey, AES_KEY_LEN_nBYTE);
    memcpy(se05x_sessionMacKey, macKey, AES_KEY_LEN_nBYTE);
    memcpy(se05x_sessionRmacKey, rMacKey, AES_KEY_LEN_nBYTE);

    return SM_OK;
}

smStatus_t Se05x_API_SCP03_SetMcvCounter(pSe05xSession_t pSessionCtx,
    const uint8_t *pCounter,
    const size_t counterLen,
    const uint8_t *pMcv,
    const size_t mcvLen)
{
    ENSURE_OR_RETURN_ON_ERROR(pSessionCtx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pCounter != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pMcv != NULL, SM_NOT_OK);

    ENSURE_OR_RETURN_ON_ERROR(counterLen == sizeof(se05x_cCounter), SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(mcvLen == sizeof(se05x_mcv), SM_NOT_OK);

    memcpy(se05x_cCounter, pCounter, sizeof(se05x_cCounter));
    memcpy(se05x_mcv, pMcv, sizeof(se05x_mcv));

    return SM_OK;
}

static int nxScp03_GP_InitializeUpdate(pSe05xSession_t session_ctx,
    uint8_t *hostChallenge,
    size_t hostChallengeLen,
    uint8_t *keyDivData,
    uint16_t *pKeyDivDataLen,
    uint8_t *keyInfo,
    uint16_t *pKeyInfoLen,
    uint8_t *cardChallenge,
    uint16_t *pCardChallengeLen,
    uint8_t *cardCryptoGram,
    uint16_t *pCardCryptoGramLen)
{
    smStatus_t retStatus        = SM_NOT_OK;
    uint8_t keyVersion          = 0x0b;
    uint8_t *pRspbuf            = NULL;
    size_t rspbufLen            = sizeof(session_ctx->apdu_buffer);
    tlvHeader_t hdr             = {{CLA_GP_7816, INS_GP_INITIALIZE_UPDATE, keyVersion, 0x00}};
    uint16_t parsePos           = 0;
    uint32_t iuResponseLenSmall = SCP_GP_IU_KEY_DIV_DATA_LEN + SCP_GP_IU_KEY_INFO_LEN + SCP_GP_CARD_CHALLENGE_LEN +
                                  SCP_GP_IU_CARD_CRYPTOGRAM_LEN + SCP_GP_SW_LEN;
    uint32_t iuResponseLenBig = SCP_GP_IU_KEY_DIV_DATA_LEN + SCP_GP_IU_KEY_INFO_LEN + SCP_GP_CARD_CHALLENGE_LEN +
                                SCP_GP_IU_CARD_CRYPTOGRAM_LEN + SCP_GP_IU_SEQ_COUNTER_LEN + SCP_GP_SW_LEN;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(keyDivData != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pKeyDivDataLen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(keyInfo != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pKeyInfoLen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pCardChallengeLen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardCryptoGram != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pCardCryptoGramLen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR((hostChallengeLen < UINT8_MAX), 1);

    ENSURE_OR_RETURN_ON_ERROR(*pKeyDivDataLen == SCP_GP_IU_KEY_DIV_DATA_LEN, 1);
    ENSURE_OR_RETURN_ON_ERROR(*pKeyInfoLen == SCP_GP_IU_KEY_INFO_LEN, 1);
    ENSURE_OR_RETURN_ON_ERROR(*pCardChallengeLen == SCP_GP_CARD_CHALLENGE_LEN, 1);
    ENSURE_OR_RETURN_ON_ERROR(*pCardCryptoGramLen == SCP_GP_IU_CARD_CRYPTOGRAM_LEN, 1);

    pRspbuf = &session_ctx->apdu_buffer[0];

    memcpy(session_ctx->apdu_buffer, &hdr, 4);
    session_ctx->apdu_buffer[4] = hostChallengeLen;

    ENSURE_OR_RETURN_ON_ERROR(hostChallengeLen < (MAX_APDU_BUFFER - 5), 1);
    memcpy((session_ctx->apdu_buffer + 5), hostChallenge, hostChallengeLen);

    SMLOG_D("Sending GP Initialize Update Command !!! \n");
    retStatus = smComT1oI2C_TransceiveRaw(
        session_ctx->conn_context, session_ctx->apdu_buffer, (hostChallengeLen + 5), pRspbuf, &rspbufLen);
    if (retStatus != SM_OK) {
        SMLOG_D("Error in sending GP Initialize Update Command \n");
        return 1;
    }

    // Parse Response
    // The expected result length depends on random (HOST-Channel) or pseudo-random (ADMIN-Channel) challenge type.
    // The pseudo-random challenge case also includes a 3 byte sequence counter
    if ((rspbufLen != iuResponseLenSmall) && (rspbufLen != iuResponseLenBig)) {
        // Note: A response of length 2 (a proper SW) is also collapsed into return code SCP_FAIL
        SMLOG_D("GP_InitializeUpdate Unexpected amount of data returned \n");
        return 1;
    }

    memcpy(keyDivData, pRspbuf, SCP_GP_IU_KEY_DIV_DATA_LEN);
    parsePos = SCP_GP_IU_KEY_DIV_DATA_LEN;
    memcpy(keyInfo, &(pRspbuf[parsePos]), SCP_GP_IU_KEY_INFO_LEN);
    parsePos += SCP_GP_IU_KEY_INFO_LEN;
    memcpy(cardChallenge, &(pRspbuf[parsePos]), SCP_GP_CARD_CHALLENGE_LEN);
    parsePos += SCP_GP_CARD_CHALLENGE_LEN;
    memcpy(cardCryptoGram, &(pRspbuf[parsePos]), SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    parsePos += SCP_GP_IU_CARD_CRYPTOGRAM_LEN;

    // Construct Return Value
    retStatus = (pRspbuf[rspbufLen - 2] << 8) + pRspbuf[rspbufLen - 1];
    if (retStatus == SM_OK) {
        SMLOG_MAU8_D(" Output: keyDivData", keyDivData, *pKeyDivDataLen);
        SMLOG_MAU8_D(" Output: keyInfo", keyInfo, *pKeyInfoLen);
        SMLOG_MAU8_D(" Output: cardChallenge", cardChallenge, *pCardChallengeLen);
        SMLOG_MAU8_D(" Output: cardCryptoGram", cardCryptoGram, *pCardCryptoGramLen);
    }
    else {
        return 1;
    }

    return 0;
}

static int nxScp03_Generate_SessionKey(
    uint8_t *key, size_t keylen, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen)
{
    ENSURE_OR_RETURN_ON_ERROR(key != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(inData != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(outSignature != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(outSignatureLen != NULL, 1);
    return hcrypto_cmac_oneshot(key, keylen, inData, inDataLen, outSignature, outSignatureLen);
}

static int nxScp03_setDerivationData(uint8_t ddA[],
    uint16_t *pDdALen,
    uint8_t ddConstant,
    uint16_t ddL,
    uint8_t iCounter,
    const uint8_t *context,
    uint16_t contextLen)
{
    ENSURE_OR_RETURN_ON_ERROR(ddA != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(pDdALen != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(context != NULL, 1);

    // SCPO3 spec p9&10
    memset(ddA, 0, DD_LABEL_LEN - 1);
    ddA[DD_LABEL_LEN - 1] = ddConstant;
    ddA[DD_LABEL_LEN]     = 0x00; // Separation Indicator
    ddA[DD_LABEL_LEN + 1] = (uint8_t)(ddL >> 8);
    ddA[DD_LABEL_LEN + 2] = (uint8_t)ddL;
    ddA[DD_LABEL_LEN + 3] = iCounter;
    memcpy(&ddA[DD_LABEL_LEN + 4], context, contextLen);
    *pDdALen = DD_LABEL_LEN + 4 + contextLen;

    return 0;
}

static int nxScp03_HostLocal_CalculateSessionKeys(
    pSe05xSession_t session_ctx, uint8_t *hostChallenge, uint8_t *cardChallenge)
{
    int ret             = 0;
    uint8_t *ddA        = NULL;
    uint16_t ddALen     = DAA_BUFFER_LEN;
    uint8_t *context    = NULL;
    uint16_t contextLen = 0;
    size_t signatureLen = AES_KEY_LEN_nBYTE;

    ENSURE_OR_RETURN_ON_ERROR((DAA_BUFFER_LEN + CONTEXT_LENGTH) <= MAX_APDU_BUFFER, 1);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardChallenge != NULL, 1);

    ddA     = session_ctx->apdu_buffer;                    // Len --> DAA_BUFFER_LEN
    context = (session_ctx->apdu_buffer + DAA_BUFFER_LEN); // Len --> CONTEXT_LENGTH

    // Calculate the Derviation data
    memcpy(context, hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    memcpy(&context[SCP_GP_HOST_CHALLENGE_LEN], cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);
    contextLen = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;

    // Set the Derviation data
    SMLOG_D("Set the Derviation data to generate Session ENC key \n");
    ret = nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SENC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);

    // Calculate the Session-ENC key
    ret = nxScp03_Generate_SessionKey(
        session_ctx->pScp03_enc_key, session_ctx->scp03_enc_key_len, ddA, ddALen, se05x_sessionEncKey, &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D(" Output:se05x_sessionEncKey ==>", se05x_sessionEncKey, AES_KEY_LEN_nBYTE);

    // Set the Derviation data
    SMLOG_D("Set the Derviation data to generate Session MAC key \n");
    ret = nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);
    // Calculate the Session-MAC key
    ret = nxScp03_Generate_SessionKey(
        session_ctx->pScp03_mac_key, session_ctx->scp03_mac_key_len, ddA, ddALen, se05x_sessionMacKey, &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D(" Output:se05x_sessionMacKey ==>", se05x_sessionMacKey, AES_KEY_LEN_nBYTE);

    /* Generation and Creation of Session RMAC SSS Key Object */
    // Set the Derviation data
    SMLOG_D("Set the Derviation data to generate Session RMAC key \n");
    ret = nxScp03_setDerivationData(
        ddA, &ddALen, DATA_DERIVATION_SRMAC, DATA_DERIVATION_L_128BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);
    // Calculate the Session-RMAC key
    ret = nxScp03_Generate_SessionKey(
        session_ctx->pScp03_mac_key, session_ctx->scp03_mac_key_len, ddA, ddALen, se05x_sessionRmacKey, &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D("Output:se05x_sessionRmacKey ==>", se05x_sessionRmacKey, AES_KEY_LEN_nBYTE);

    return 0;
}

static int nxScp03_HostLocal_VerifyCardCryptogram(pSe05xSession_t session_ctx,
    uint8_t *key,
    size_t keylen,
    uint8_t *hostChallenge,
    uint8_t *cardChallenge,
    uint8_t *cardCryptogram)
{
    uint8_t *ddA                      = NULL;
    uint16_t ddALen                   = DAA_BUFFER_LEN;
    uint8_t *context                  = NULL;
    uint16_t contextLen               = 0;
    uint8_t *cardCryptogramFullLength = NULL;
    size_t signatureLen               = AES_KEY_LEN_nBYTE;
    int ret                           = 0;

    ENSURE_OR_RETURN_ON_ERROR((DAA_BUFFER_LEN + CONTEXT_LENGTH + AES_KEY_LEN_nBYTE) <= MAX_APDU_BUFFER, 1);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(key != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardCryptogram != NULL, 1);

    ddA     = session_ctx->apdu_buffer;                    // Len --> DAA_BUFFER_LEN
    context = (session_ctx->apdu_buffer + DAA_BUFFER_LEN); // Len --> CONTEXT_LENGTH
    cardCryptogramFullLength =
        (session_ctx->apdu_buffer + DAA_BUFFER_LEN + CONTEXT_LENGTH); // Len --> AES_KEY_LEN_nBYTE

    memcpy(context, hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    memcpy(&context[SCP_GP_HOST_CHALLENGE_LEN], cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);
    contextLen = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;

    ret = nxScp03_setDerivationData(
        ddA, &ddALen, DATA_CARD_CRYPTOGRAM, DATA_DERIVATION_L_64BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);

    ret = nxScp03_Generate_SessionKey(key, keylen, ddA, ddALen, cardCryptogramFullLength, &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }
    SMLOG_MAU8_D(" Output:cardCryptogram ==>", cardCryptogramFullLength, AES_KEY_LEN_nBYTE);

    // Verify whether the 8 left most byte of cardCryptogramFullLength match cardCryptogram
    if (memcmp(cardCryptogramFullLength, cardCryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN) != 0) {
        return 1;
    }

    return 0;
}

static int nxScp03_HostLocal_CalculateHostCryptogram(pSe05xSession_t session_ctx,
    uint8_t *key,
    size_t keylen,
    uint8_t *hostChallenge,
    uint8_t *cardChallenge,
    uint8_t *hostCryptogram)
{
    uint8_t *ddA                      = NULL;
    uint16_t ddALen                   = DAA_BUFFER_LEN;
    uint8_t *context                  = NULL;
    uint16_t contextLen               = 0;
    uint8_t *hostCryptogramFullLength = NULL;
    size_t signatureLen               = AES_KEY_LEN_nBYTE;
    int ret                           = 0;

    ENSURE_OR_RETURN_ON_ERROR((DAA_BUFFER_LEN + CONTEXT_LENGTH + AES_KEY_LEN_nBYTE) <= MAX_APDU_BUFFER, 1);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(key != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(cardChallenge != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostCryptogram != NULL, 1);

    ddA     = session_ctx->apdu_buffer;                    // Len --> DAA_BUFFER_LEN
    context = (session_ctx->apdu_buffer + DAA_BUFFER_LEN); // Len --> CONTEXT_LENGTH
    hostCryptogramFullLength =
        (session_ctx->apdu_buffer + DAA_BUFFER_LEN + CONTEXT_LENGTH); // Len --> AES_KEY_LEN_nBYTE

    memcpy(context, hostChallenge, SCP_GP_HOST_CHALLENGE_LEN);
    memcpy(&context[SCP_GP_HOST_CHALLENGE_LEN], cardChallenge, SCP_GP_CARD_CHALLENGE_LEN);
    contextLen = SCP_GP_HOST_CHALLENGE_LEN + SCP_GP_CARD_CHALLENGE_LEN;

    ret = nxScp03_setDerivationData(
        ddA, &ddALen, DATA_HOST_CRYPTOGRAM, DATA_DERIVATION_L_64BIT, DATA_DERIVATION_KDF_CTR, context, contextLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, 1);

    ret = nxScp03_Generate_SessionKey(key, keylen, ddA, ddALen, hostCryptogramFullLength, &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in nxScp03_Generate_SessionKey");
        return 1;
    }

    SMLOG_MAU8_D(" Output:hostCryptogram ==>", hostCryptogramFullLength, AES_KEY_LEN_nBYTE);

    // Chop of the tail of the hostCryptogramFullLength
    memcpy(hostCryptogram, hostCryptogramFullLength, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    return 0;
}

static int nxScp03_GP_ExternalAuthenticate(
    pSe05xSession_t session_ctx, uint8_t *key, size_t keylen, uint8_t *updateMCV, uint8_t *hostCryptogram)
{
    uint8_t *txBuf                      = NULL;
    uint8_t macToAdd[AES_KEY_LEN_nBYTE] = {0};
    smStatus_t retStatus                = SM_NOT_OK;
    int ret                             = 0;
    size_t signatureLen                 = sizeof(macToAdd);
    size_t rspbufLen                    = MAX_APDU_BUFFER;

    tlvHeader_t hdr = {
        {CLA_GP_7816 | CLA_GP_SECURITY_BIT, INS_GP_EXTERNAL_AUTHENTICATE, SECLVL_CDEC_RENC_CMAC_RMAC, 0x00}};

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(key != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(updateMCV != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(hostCryptogram != NULL, 1);

    txBuf    = (session_ctx->apdu_buffer + (MAX_APDU_BUFFER / 2));
    txBuf[0] = CLA_GP_7816 | CLA_GP_SECURITY_BIT; //Set CLA Byte
    txBuf[1] = INS_GP_EXTERNAL_AUTHENTICATE;      //Set INS Byte
    txBuf[2] = SECLVL_CDEC_RENC_CMAC_RMAC;        //Set Security Level
    txBuf[3] = 0x00;
    txBuf[4] = 0x10; // The Lc value is set as-if the MAC has already been appended (SCP03 spec p16. Fig.61)
    memcpy(&txBuf[5], hostCryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    /*
    * For the EXTERNAL AUTHENTICATE command MAC verification, the "MAC chaining value" is set to 16
    * bytes '00'. (SCP03 spec p16)
    */

    /* Check for txBuf */ ENSURE_OR_RETURN_ON_ERROR(
        (5 + (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN)) <= (MAX_APDU_BUFFER / 2), 1);
    /* Check for apdu_buffer */ ENSURE_OR_RETURN_ON_ERROR(
        (SCP_MCV_LEN + 5 + SCP_GP_IU_CARD_CRYPTOGRAM_LEN) <= (MAX_APDU_BUFFER / 2), 1);

    memset(updateMCV, 0, SCP_MCV_LEN);
    memcpy(session_ctx->apdu_buffer, updateMCV, SCP_MCV_LEN);
    memcpy((session_ctx->apdu_buffer + SCP_MCV_LEN), txBuf, (5 + SCP_GP_IU_CARD_CRYPTOGRAM_LEN));

    ret = hcrypto_cmac_oneshot(key,
        keylen,
        session_ctx->apdu_buffer,
        (SCP_MCV_LEN + 5 + SCP_GP_IU_CARD_CRYPTOGRAM_LEN),
        macToAdd,
        &signatureLen);
    if (ret != 0) {
        SMLOG_D("Error in hcrypto_cmac_oneshot");
        return 1;
    }

    SMLOG_MAU8_D(" Output: Calculated MAC ==>", macToAdd, signatureLen);

    SMLOG_D("Add calculated MAC Value to cmd Data");
    memcpy(updateMCV, macToAdd, AES_KEY_LEN_nBYTE);
    memcpy(&txBuf[5 + SCP_GP_IU_CARD_CRYPTOGRAM_LEN], macToAdd, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    SMLOG_D("Sending GP External Authenticate Command !!!");

    memcpy(session_ctx->apdu_buffer, &hdr, 4);
    session_ctx->apdu_buffer[4] = (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN);
    memcpy((session_ctx->apdu_buffer + 5), &txBuf[5], (2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN));

    retStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context,
        session_ctx->apdu_buffer,
        ((2 * SCP_GP_IU_CARD_CRYPTOGRAM_LEN) + 5),
        session_ctx->apdu_buffer,
        &rspbufLen);
    if (retStatus != SM_OK) {
        SMLOG_D("GP_ExternalAuthenticate transmit failed");
        return 1;
    }

    return 0;
}

smStatus_t Se05x_API_SCP03_CreateSession(pSe05xSession_t session_ctx)
{
    int ret = 0;
#ifdef INITIAL_HOST_CHALLANGE
    uint8_t hostChallenge[] = INITIAL_HOST_CHALLANGE;
#else
    uint8_t hostChallenge[8] = {
        0,
    };
#endif
    size_t hostChallenge_len = sizeof(hostChallenge);
    uint8_t keyDivData[SCP_GP_IU_KEY_DIV_DATA_LEN];
    uint16_t keyDivDataLen = sizeof(keyDivData);
    uint8_t keyInfo[SCP_GP_IU_KEY_INFO_LEN];
    uint16_t keyInfoLen = sizeof(keyInfo);
    uint8_t cardChallenge[SCP_GP_CARD_CHALLENGE_LEN];
    uint16_t cardChallengeLen = sizeof(cardChallenge);
    uint8_t cardCryptoGram[SCP_GP_IU_CARD_CRYPTOGRAM_LEN];
    uint16_t cardCryptoGramLen = sizeof(cardCryptoGram);
    uint8_t hostCryptogram[SCP_GP_IU_CARD_CRYPTOGRAM_LEN];
    const uint8_t commandCounter[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    if (session_ctx->pScp03_enc_key == NULL || session_ctx->pScp03_mac_key == NULL) {
        SMLOG_E("PlatformSCP03 keys (ENC and MAC) are not set. Set the keys in session context in application ! \n");
        return SM_NOT_OK;
    }
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_enc_key_len == SCP_KEY_SIZE, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_mac_key_len == SCP_KEY_SIZE, SM_NOT_OK);

    session_ctx->scp03_session = 0;

#ifndef INITIAL_HOST_CHALLANGE
    ret = hcrypto_get_random(hostChallenge, hostChallenge_len);
    ENSURE_OR_RETURN_ON_ERROR((ret == 0), SM_NOT_OK);
#endif

    SMLOG_MAU8_D(" hostChallenge ==>", hostChallenge, hostChallenge_len);

    ret = nxScp03_GP_InitializeUpdate(session_ctx,
        hostChallenge,
        hostChallenge_len,
        keyDivData,
        &keyDivDataLen,
        keyInfo,
        &keyInfoLen,
        cardChallenge,
        &cardChallengeLen,
        cardCryptoGram,
        &cardCryptoGramLen);
    if (ret != 0) {
        SMLOG_E("Error in nxScp03_GP_InitializeUpdate");
        return SM_NOT_OK;
    }

    ret = nxScp03_HostLocal_CalculateSessionKeys(session_ctx, hostChallenge, cardChallenge);
    if (ret != 0) {
        SMLOG_E("Error in nxScp03_HostLocal_CalculateSessionKeys");
        return SM_NOT_OK;
    }

    ret = nxScp03_HostLocal_VerifyCardCryptogram(
        session_ctx, se05x_sessionMacKey, AES_KEY_LEN_nBYTE, hostChallenge, cardChallenge, cardCryptoGram);
    if (ret != 0) {
        SMLOG_E("Error in nxScp03_HostLocal_VerifyCardCryptogram");
        //Most likely, SCP03 keys are not correct"
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("cardCryptoGram ==>", cardCryptoGram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    SMLOG_D("CardCryptogram verified successfully...Calculate HostCryptogram \n");

    ret = nxScp03_HostLocal_CalculateHostCryptogram(
        session_ctx, se05x_sessionMacKey, AES_KEY_LEN_nBYTE, hostChallenge, cardChallenge, hostCryptogram);
    if (ret != 0) {
        SMLOG_E("Error in nxScp03_HostLocal_CalculateHostCryptogram");
        return SM_NOT_OK;
    }

    SMLOG_MAU8_D("hostCryptogram ==>", hostCryptogram, SCP_GP_IU_CARD_CRYPTOGRAM_LEN);

    ret =
        nxScp03_GP_ExternalAuthenticate(session_ctx, se05x_sessionMacKey, AES_KEY_LEN_nBYTE, se05x_mcv, hostCryptogram);
    if (ret != 0) {
        SMLOG_E("GP_ExternalAuthenticate failed \n"); // with Status %04X", status);
        return SM_NOT_OK;
    }
    else {
        // At this stage we have authenticated successfully.
        memcpy(se05x_cCounter, commandCounter, AES_KEY_LEN_nBYTE);
        SMLOG_D("Authentication Successful!!! \n");
    }

    session_ctx->scp03_session = 1;
    return SM_OK;
}

/**************** Data transmit functions *****************/

smStatus_t Se05x_API_SCP03_PadCommandAPDU(pSe05xSession_t session_ctx, uint8_t *cmdBuf, size_t *pCmdBufLen)
{
    uint16_t zeroBytesToPad = 0;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(cmdBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pCmdBufLen != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(((UINT_MAX - 1) >= (*pCmdBufLen)), SM_NOT_OK);

    // pad the payload and adjust the length of the APDU
    cmdBuf[(*pCmdBufLen)] = SCP_DATA_PAD_BYTE;
    *pCmdBufLen += 1;
    zeroBytesToPad = (SCP_KEY_SIZE - ((*pCmdBufLen) % SCP_KEY_SIZE)) % SCP_KEY_SIZE;
    while (zeroBytesToPad > 0) {
        cmdBuf[(*pCmdBufLen)] = 0x00;
        ENSURE_OR_RETURN_ON_ERROR(((UINT_MAX - 1) >= (*pCmdBufLen)), SM_NOT_OK);
        *pCmdBufLen += 1;
        zeroBytesToPad--;
    }

    return SM_OK;
}

smStatus_t Se05x_API_SCP03_CalculateCommandICV(pSe05xSession_t session_ctx, uint8_t *pIcv)
{
    int ret                      = 0;
    smStatus_t retStatus         = SM_NOT_OK;
    uint8_t ivZero[SCP_KEY_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pIcv != NULL, SM_NOT_OK);

    ret = hcrypto_aes_cbc_encrypt(
        se05x_sessionEncKey, AES_KEY_LEN_nBYTE, ivZero, SCP_KEY_SIZE, se05x_cCounter, pIcv, SCP_KEY_SIZE);

    retStatus = (ret == 0) ? (SM_OK) : (SM_NOT_OK);
    return retStatus;
}

void Se05x_API_SCP03_IncCommandCounter(pSe05xSession_t session_ctx)
{
    int i = 15;

    (void)session_ctx;

    while (i > 0) {
        if (se05x_cCounter[i] < 255) {
            se05x_cCounter[i] += 1;
            break;
        }
        else {
            se05x_cCounter[i] = 0;
            i--;
        }
    }
    return;
}

static void nxpSCP03_Dec_CommandCounter(uint8_t *pCtrblock)
{
    int i = 15;
    while (i > 0) {
        if (pCtrblock[i] == 0) {
            pCtrblock[i] = 0xFF;
            i--;
        }
        else {
            pCtrblock[i]--;
            break;
        }
    }

    return;
}

smStatus_t Se05x_API_SCP03_GetResponseICV(pSe05xSession_t session_ctx, uint8_t *pIcv, bool hasCmd)
{
    uint8_t ivZero[SCP_IV_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t dataLen                          = 0;
    uint8_t paddedCounterBlock[SCP_IV_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int ret              = 0;
    smStatus_t retStatus = SM_NOT_OK;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pIcv != NULL, SM_NOT_OK);

    memcpy(paddedCounterBlock, se05x_cCounter, SCP_KEY_SIZE);
    if ((0 /*pdySCP03SessCtx->authType == kSSS_AuthType_SCP03*/) && (!hasCmd)) {
        nxpSCP03_Dec_CommandCounter(paddedCounterBlock);
    }
    paddedCounterBlock[0] = SCP_DATA_PAD_BYTE; // MSB padded with 0x80 Section 6.2.7 of SCP03 spec
    dataLen               = SCP_KEY_SIZE;

    ret = hcrypto_aes_cbc_encrypt(
        se05x_sessionEncKey, AES_KEY_LEN_nBYTE, ivZero, SCP_KEY_SIZE, paddedCounterBlock, pIcv, dataLen);

    retStatus = (ret == 0) ? (SM_OK) : (SM_NOT_OK);
    return retStatus;
}

smStatus_t Se05x_API_SCP03_RestoreSwRAPDU(pSe05xSession_t session_ctx,
    uint8_t *rspBuf,
    size_t *pRspBufLen,
    uint8_t *plaintextResponse,
    size_t plaintextRespLen,
    uint8_t *sw)
{
    size_t i            = plaintextRespLen;
    int removePaddingOk = 0;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rspBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pRspBufLen != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(plaintextResponse != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(sw != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR((plaintextRespLen >= SCP_KEY_SIZE), SM_NOT_OK);

    while ((i > 1) && (i > (plaintextRespLen - SCP_KEY_SIZE))) {
        if (plaintextResponse[i - 1] == 0x00) {
            i--;
        }
        else if (plaintextResponse[i - 1] == SCP_DATA_PAD_BYTE) {
            // We have found padding delimitor
            memcpy(&plaintextResponse[i - 1], sw, SCP_GP_SW_LEN);

            if (*pRspBufLen < plaintextRespLen) {
                // response buffer is small
                return SM_NOT_OK;
            }
            ENSURE_OR_RETURN_ON_ERROR(((UINT_MAX - 1) >= i), SM_NOT_OK);
            memcpy(rspBuf, plaintextResponse, i + 1);
            *pRspBufLen = (i + 1);

            removePaddingOk = 1;
            break;
        }
        else {
            // We've found a non-padding character while removing padding
            // Most likely the cipher text was not properly decoded.
            SMLOG_D("RAPDU Decoding failed No Padding found");
            break;
        }
    }

    if (removePaddingOk == 0) {
        return SM_NOT_OK;
    }

    return SM_OK;
}

smStatus_t Se05x_API_SCP03_CalculateMacRspApdu(
    pSe05xSession_t session_ctx, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen)
{
    int ret        = 0;
    void *cmac_ctx = NULL;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);

    cmac_ctx = hcrypto_cmac_setup(se05x_sessionRmacKey, AES_KEY_LEN_nBYTE);
    ENSURE_OR_RETURN_ON_ERROR(cmac_ctx != NULL, SM_NOT_OK);

    ret = hcrypto_cmac_init(cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, se05x_mcv, SCP_KEY_SIZE);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(inDataLen >= 10, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, inData, inDataLen - 8 - 2);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, (inData + (inDataLen - 2)), 2);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_final(cmac_ctx, outSignature, outSignatureLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);

    return SM_OK;
}

smStatus_t Se05x_API_SCP03_CalculateMacCmdApdu(
    pSe05xSession_t session_ctx, uint8_t *inData, size_t inDataLen, uint8_t *outSignature, size_t *outSignatureLen)
{
    int ret        = 0;
    void *cmac_ctx = NULL;

    ENSURE_OR_RETURN_ON_ERROR(session_ctx != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(session_ctx->scp03_session == 1, SM_NOT_OK);

    cmac_ctx = hcrypto_cmac_setup(se05x_sessionMacKey, AES_KEY_LEN_nBYTE);
    ENSURE_OR_RETURN_ON_ERROR(cmac_ctx != NULL, SM_NOT_OK);

    ret = hcrypto_cmac_init(cmac_ctx);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, se05x_mcv, SCP_KEY_SIZE);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_update(cmac_ctx, inData, inDataLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);
    ret = hcrypto_cmac_final(cmac_ctx, outSignature, outSignatureLen);
    ENSURE_OR_RETURN_ON_ERROR(ret == 0, SM_NOT_OK);

    memcpy(se05x_mcv, outSignature, SCP_MCV_LEN);
    return SM_OK;
}

smStatus_t Se05x_API_SCP03_TransmitData(pSe05xSession_t session_ctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen,
    uint8_t hasle)
{
    smStatus_t apduStatus = SM_NOT_OK;
    int ret               = 0;
    size_t tempRspBufLen  = 0;
    int i                 = 0;
    size_t macDataLen  = 16;
    size_t tagLen = 16;
    size_t nonceLen = 16;
    size_t se05xCmdLC  = 0;
    size_t se05xCmdLCW = 2;
    size_t se05xRspLCW = 2;
    size_t rspHdrLen = 2;
    uint8_t sw[SCP_GP_SW_LEN];
    size_t compareoffset                 = 0;
    size_t actualRespLen                 = 0;
    uint8_t se05x_mcv_tmp[SCP_CMAC_SIZE] = {
        0,
    };
    uint8_t isMACverified; /* Added by me. */

    ENSURE_OR_RETURN_ON_ERROR(hdr != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(cmdBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(rspBuf != NULL, SM_NOT_OK);
    ENSURE_OR_RETURN_ON_ERROR(pRspBufLen != NULL, SM_NOT_OK);

    tempRspBufLen = *pRspBufLen;

    memmove(cmdBuf + sizeof(*hdr) + se05xCmdLCW, cmdBuf, cmdBufLen); /* "Displace" the payload by six positions to the "right", so as to make room for the CAPDU header. */
    memcpy(cmdBuf, hdr, sizeof(*hdr)); /* Note: here "header" refers to CLA, INS, P1, P2 bytes. */
    cmdBuf[0] |= 0x4; /* Proprietary SM. */
    i += sizeof(*hdr);

    if(se05x_sessionStatus == UNINITIATED){
        /* Generate nonceH. The nonce should be randomly generated and not constant, as it is in the current (temporary) implementation. */
        se05xCmdLC = cmdBufLen + nonceLen + macDataLen; /* Remember that, since Lc' is used as AD it must be updated to the correct value before AEAD encryption is applied. */

        cmdBuf[i++] = (uint8_t) (0xFFu & (se05xCmdLC >> 8)); /* Adjust the Lc field. */
        cmdBuf[i++] = (uint8_t) (0xFFu & (se05xCmdLC));	/* Adjust the Lc field. */

	Xoodyak_Initialize(&instance, se05x_staticKey, 16, idK, 16, counterK, 16); /* Initialize the Xoodyak instance with the static key, the key id, and the counter. */
	Xoodyak_Absorb(&instance, nonceH, nonceLen); /* Absorb the host nonce (AD). */
	Xoodyak_Ratchet(&instance); /* Transform the Xoodyak state in an irreversible way by calling the Ratchet function. */
	Xoodyak_Absorb(&instance, cmdBuf, (sizeof(*hdr) + se05xCmdLCW)); /* Absorb the CAPDU header bytes (AD). */
	Xoodyak_Encrypt(&instance, cmdBuf + sizeof(*hdr) + se05xCmdLCW, cmdBuf + sizeof(*hdr) + se05xCmdLCW, (size_t)cmdBufLen); /* Encrypt the CAPDU payload. */
	Xoodyak_Squeeze(&instance, cmdBuf + sizeof(*hdr) + se05xCmdLCW + cmdBufLen, macDataLen); /* Generate the authentication tag. */
	cmdBufLen = cmdBufLen + macDataLen; /* Update the payload length to account for the addition of the authenticationt tag. */

        memcpy(cmdBuf + sizeof(*hdr) + se05xCmdLCW + cmdBufLen, nonceH, nonceLen);  /* Add nonceH to command payload. */
        cmdBufLen += nonceLen; /* To account for nonceH. */
        se05x_sessionStatus = HANDSHAKE; /* Update the state of the secure channel. */
        //counterK++;
    }else{
        se05xCmdLC = cmdBufLen + macDataLen; /* Payload length + MAC. */
        cmdBuf[i++] = (uint8_t) (0xFFu & (se05xCmdLC >> 8)); /* Adjust the Lc field */
        cmdBuf[i++] = (uint8_t) (0xFFu & (se05xCmdLC)); /* Adjust the Lc field. */

	Xoodyak_Absorb(&instance, cmdBuf, (sizeof(*hdr) + se05xCmdLCW)); /* Absorb the CAPDU header bytes (AD). */
	Xoodyak_Encrypt(&instance, cmdBuf + sizeof(*hdr) + se05xCmdLCW, cmdBuf + sizeof(*hdr) + se05xCmdLCW, (size_t) cmdBufLen); /* Encrypt the CAPDU payload. */
	Xoodyak_Squeeze(&instance, cmdBuf + sizeof(*hdr) + se05xCmdLCW + cmdBufLen, macDataLen); /* Generate the authentication tag. */
	cmdBufLen = cmdBufLen + macDataLen; /* Update the payload length to account for the addition of the authenticationt tag. */
    }

    if (cmdBufLen > 0) {
        i += cmdBufLen;
    }

    if (hasle) {
       cmdBuf[i++] = 0x00;
       cmdBuf[i++] = 0x00;
    }

    apduStatus = smComT1oI2C_TransceiveRaw(session_ctx->conn_context, cmdBuf, i, rspBuf, &tempRspBufLen);
    ENSURE_OR_RETURN_ON_ERROR((apduStatus == SM_OK), apduStatus);
    ENSURE_OR_RETURN_ON_ERROR((tempRspBufLen >= SCP_GP_SW_LEN), SM_NOT_OK);

    apduStatus = rspBuf[tempRspBufLen - 2] << 8 | rspBuf[tempRspBufLen - 1];
    if (apduStatus == SM_OK) {
        memcpy(sw, &(rspBuf[tempRspBufLen - SCP_GP_SW_LEN]), SCP_GP_SW_LEN);

        if(se05x_sessionStatus == HANDSHAKE){
            memcpy(nonceSE, rspBuf + (tempRspBufLen - SCP_GP_SW_LEN - nonceLen), nonceLen); /* Extract nonceSE. */

	    Xoodyak_Absorb(&instance, rspBuf, rspHdrLen + se05xRspLCW); /* Absorb the RAPDU header bytes and Lc bytes (AD). */
	    Xoodyak_Absorb(&instance, rspBuf + tempRspBufLen - 2, 1); /* Absorb SW1 byte (AD). */
	    Xoodyak_Absorb(&instance, rspBuf + tempRspBufLen - 1, 1); /* Absorb SW2 byte SW2 (AD). */
	    Xoodyak_Absorb(&instance, nonceSE, nonceLen); /* Absorb nonceSE (AD).*/

            tempRspBufLen -= (rspHdrLen + se05xRspLCW + nonceLen + SCP_GP_SW_LEN); /* Record the RAPDU payload length by excluding the header bytes, the SW bytes and the nonceSE bytes. */

	    tempRspBufLen = tempRspBufLen - macDataLen; /* Exclude the authentication tag bytes from the decryption process. */
	    Xoodyak_Decrypt(&instance, rspBuf + rspHdrLen + se05xRspLCW, rspBuf + rspHdrLen + se05xRspLCW, (size_t) tempRspBufLen); /* Decrypt the RAPDU payload. */
	    Xoodyak_Squeeze(&instance, tag, macDataLen); /* Re-calculate the authentication tag to compare it with the received authentication tag. */
	    if(memcmp(tag, rspBuf + rspHdrLen + se05xRspLCW + tempRspBufLen, macDataLen) != 0){ /* Check if the tags are identical. */
		memset(rspBuf + rspHdrLen + se05xRspLCW, 0, (size_t)tempRspBufLen);
		isMACVerified = -1;
	    } else {
		isMACVerified = 0;
	    }

            tempRspBufLen += rspHdrLen + se05xRspLCW; /* Record the length of the entire response, that is header + payload (without the authentication tag). */
            se05x_sessionStatus = ACTIVE;
        } else{
	    Xoodyak_Absorb(&instance, rspBuf, rspHdrLen + se05xRspLCW); /* Absorb the RAPDU header bytes and Lc bytes (AD). */
            Xoodyak_Absorb(&instance, rspBuf + tempRspBufLen - 2, 1); /* Absorb SW1 byte (AD). */
            Xoodyak_Absorb(&instance, rspBuf + tempRspBufLen - 1, 1); /* Absorb SW2 byte (AD). */

            tempRspBufLen -= (rspHdrLen + se05xRspLCW + SCP_GP_SW_LEN); /* Record the RAPDU payload length by excluding the header bytes, and the SW bytes. */

            tempRspBufLen = tempRspBufLen - macDataLen; /* Exclude the authentication tag bytes from the decryption process. */
            Xoodyak_Decrypt(&instance, rspBuf + rspHdrLen + se05xRspLCW, rspBuf + rspHdrLen + se05xRspLCW, (size_t) tempRspBufLen); /* Decrypt the RAPDU payload. */
            Xoodyak_Squeeze(&instance, tag, macDataLen); /* Re-calculate the authentication tag to compare it with the received authentication tag. */
            if(memcmp(tag, rspBuf + rspHdrLen + se05xRspLCW + tempRspBufLen, macDataLen) != 0){ /* Check if the tags are identical. */
                memset(rspBuf + rspHdrLen + se05xRspLCW, 0, (size_t)tempRspBufLen);
                isMACVerified = -1;
            } else {
                isMACVerified = 0;
            }
	    tempRspBufLen += rspHdrLen + se05xRspLCW; /* Record the RAPDU payload length by excluding the header bytes, the SW bytes and the nonceSE bytes. */
        }

        /* Adjust the Lc field of the decrypted RAPDU. */
	rspBuf[2] = (uint8_t) ((tempRspBufLen - rspHdrLen - se05xRspLCW) >> 8);
	rspBuf[3] = (uint8_t) (tempRspBufLen - rspHdrLen - se05xRspLCW);

       if(isMACVerified != 0){
         SMLOG_E(" Response MAC did not verify \n");
         return SM_NOT_OK;
       }

        SMLOG_D("RMAC verified successfully...Decrypt Response Data \n");

        actualRespLen = (tempRspBufLen) + SCP_GP_SW_LEN;

        rspBuf[actualRespLen - 2] = sw[0];
	rspBuf[actualRespLen - 1] = sw[1];

	*pRspBufLen = actualRespLen;

        SMLOG_MAU8_D("Decrypted Data ==>", rspBuf, *pRspBufLen);
    }

    return apduStatus;
}
