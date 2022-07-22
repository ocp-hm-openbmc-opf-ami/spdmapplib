/**
 * Copyright © 2022 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitation
 */
#include "library/spdm_transport_none_lib.h"

#include "mctp_wrapper.hpp"
#include "spdmapplib_impl.hpp"

#include <phosphor-logging/log.hpp>

#include <cstdint>
#include <functional>
#include <iostream>

namespace spdm_app_lib
{
/*Callback functions for libspdm */

return_status requesterDeviceSendMessage(void* spdmContext, uintn requestSize,
                                         const void* request, uint64_t timeout)
{
    void* pTmp = nullptr;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == nullptr)
    {
        return error_codes::generalReturnError;
    }
    SPDMRequesterImpl* pspdmTmp = nullptr;
    pspdmTmp = static_cast<SPDMRequesterImpl*>(pTmp);

    uint32_t j;
    std::vector<uint8_t> data;
    uint8_t* requestPayload = (uint8_t*)(request);

    data.push_back(static_cast<uint8_t>(mctpw::MessageType::spdm));

    for (j = 0; j < requestSize; j++)
    {
        data.push_back(*(requestPayload + j));
    }

    return pspdmTmp->deviceSendMessage(spdmContext, data, timeout);
}

return_status requesterDeviceReceiveMessage(void* spdmContext,
                                            uintn* responseSize, void* response,
                                            uint64_t timeout)
{
    void* pTmp = nullptr;
    return_status status;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == nullptr)
    {
        return error_codes::generalReturnError;
    }
    SPDMRequesterImpl* pspdmTmp = nullptr;
    pspdmTmp = static_cast<SPDMRequesterImpl*>(pTmp);
    std::vector<uint8_t> rspData{};
    status = pspdmTmp->deviceReceiveMessage(spdmContext, rspData, timeout);
    *responseSize = rspData.size() - 1; // skip MessageType byte
    std::copy(rspData.begin() + 1, rspData.end(),
              reinterpret_cast<uint8_t*>(response));
    return status;
}

SPDMRequesterImpl::~SPDMRequesterImpl()
{
    if (spdmResponder.pspdmContext)
    {
        free_pool(spdmResponder.pspdmContext);
        spdmResponder.pspdmContext = nullptr;
    }
}

/**
 * @brief Function to setup user assigned endpoint initial configuration.
 *
 * @return true: success, false: failure.
 *
 **/
bool SPDMRequesterImpl::settingFromConfig(void)
{
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;
    uint16_t u16Value;
    uint32_t u32Value;
    void* tmpThis = static_cast<void*>(this);
    return_status status;

    uint32_t data_size;
    useSlotCount = static_cast<uint8_t>(spdmRequesterCfg.slotcount);
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("SPDMRequesterImpl::settingFromConfig Requester useSlotCount: " +
         std::to_string(spdmRequesterCfg.slotcount))
            .c_str());

    useSlotId = 0;
    mUseMeasurementSummaryHashType =
        SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH;
    useRequesterCapabilityFlags =
        (0 | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
         SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP);
    mUseMeasurementOperation =
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
    mUseMeasurementAttribute = 0;

    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter,
                              &tmpThis, sizeof(void*));
    if (RETURN_ERROR(status))
    {
        return false;
    }
    u8Value = 0;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    useRequesterCapabilityFlags = spdmRequesterCfg.capability;
    u32Value = useRequesterCapabilityFlags;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u8Value = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u32Value = spdmRequesterCfg.measHash;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u32Value = spdmRequesterCfg.asym;
    mUseAsymAlgo = spdmRequesterCfg.asym;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u16Value = static_cast<uint16_t>(spdmRequesterCfg.reqasym);
    mUseReqAsymAlgo = static_cast<uint16_t>(spdmRequesterCfg.reqasym);
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u32Value = spdmRequesterCfg.hash;
    mUseHashAlgo = spdmRequesterCfg.hash;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u16Value = static_cast<uint16_t>(spdmRequesterCfg.dhe);
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u16Value = static_cast<uint16_t>(spdmRequesterCfg.aead);
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u16Value = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    status =
        libspdm_set_data(spdmResponder.pspdmContext, LIBSPDM_DATA_KEY_SCHEDULE,
                         &parameter, &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u8Value = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }
    /*
        This function sends GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHM
        to initialize the connection with SPDM responder.
    */

    status = libspdm_init_connection(spdmResponder.pspdmContext, false);
    if (RETURN_ERROR(status))
    {
        std::stringstream ss;
        ss << "0x" << std::uppercase << std::setfill('0') << std::setw(4)
           << std::hex << status;
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SPDMRequesterImpl::settingFromConfig libspdm_init_connection Error!- " +
             ss.str())
                .c_str());
        free_pool(spdmResponder.pspdmContext);
        spdmResponder.pspdmContext = nullptr;
        return false;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDMRequesterImpl::settingFromConfig libspdm_init_connection completed!");
    }

    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

    data_size = sizeof(u32Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_CONNECTION_STATE, &parameter,
                              &u32Value, &data_size);
    ASSERT(u32Value == LIBSPDM_CONNECTION_STATE_NEGOTIATED);
    if (RETURN_ERROR(status))
    {
        return false;
    }

    data_size = sizeof(u32Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                              &u32Value, &data_size);
    if (RETURN_ERROR(status))
    {
        return false;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("SPDMRequesterImpl::settingFromConfig use measurement hash algo: " +
         std::to_string(u32Value))
            .c_str());
    data_size = sizeof(u32Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                              &u32Value, &data_size);
    if (RETURN_ERROR(status))
    {
        return false;
    }
    mUseAsymAlgo = u32Value;
    data_size = sizeof(u32Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                              &u32Value, &data_size);
    if (RETURN_ERROR(status))
    {
        return false;
    }
    mUseHashAlgo = u32Value;
    data_size = sizeof(u16Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                              &u16Value, &data_size);
    if (RETURN_ERROR(status))
    {
        return false;
    }
    mUseReqAsymAlgo = u16Value;

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("SPDMRequesterImpl::settingFromConfig mUseAsymAlgo: " +
         std::to_string(mUseAsymAlgo))
            .c_str());
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("SPDMRequesterImpl::settingFromConfig mUseHashAlgo: " +
         std::to_string(mUseHashAlgo))
            .c_str());
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("SPDMRequesterImpl::settingFromConfig mUseReqAsymAlgo: " +
         std::to_string(mUseReqAsymAlgo))
            .c_str());

    return true;
}

/**
 * @brief Setup the configuration of user assigned endpoint as target
 *responder.
 *
 * @param  transEP          The endpoint object to be configured
 * @return bool             true indicates success and false indicates failure
 *
 **/
bool SPDMRequesterImpl::setupResponder(
    const spdm_transport::TransportEndPoint& transEP)
{
    return_status status;
    spdmResponder.pspdmContext = allocate_zero_pool(libspdm_get_context_size());
    if (spdmResponder.pspdmContext == nullptr)
    {
        return error_codes::generalReturnError;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "SPDMRequesterImpl::setupResponder");
    spdmResponder.transEP = transEP;
    spdmResponder.useSlotId = 0;
    spdmResponder.sessionId = 0;
    spdmResponder.useVersion = 0;
    spdmResponder.useReqAsymAlgo = 0;
    spdmResponder.useMeasurementHashAlgo = 0;
    spdmResponder.useAsymAlgo = 0;
    spdmResponder.useHashAlgo = 0;
    spdmResponder.connectStatus = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdmResponder.data.clear();

    status = libspdm_init_context(spdmResponder.pspdmContext);
    if (RETURN_ERROR(status))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SPDMRequesterImpl::setupResponder libspdm_init_context failed" +
             std::to_string(status))
                .c_str());
        return false;
    }
    libspdm_register_device_io_func(spdmResponder.pspdmContext,
                                    requesterDeviceSendMessage,
                                    requesterDeviceReceiveMessage);

    libspdm_register_transport_layer_func(spdmResponder.pspdmContext,
                                          spdm_transport_none_encode_message,
                                          spdm_transport_none_decode_message);

    return true;
}

/**
 * @brief Set received data to assigned endpoint.
 *
 * @param  transEP          The Endpoint object to receive data.
 * @param  trans             The pointer of transport instance.
 *
 **/
void SPDMRequesterImpl::addData(spdm_transport::TransportEndPoint& transEP,
                                const std::vector<uint8_t>& data)
{
    if (spdmResponder.transEP == transEP)
    {
        spdmResponder.data = std::move(data);
    }
}

/**
 * @brief Function to pass as parameter of syncSendRecvData of transport
 *layer.
 *
 *  The function will be called when send/receive is completed in transport
 *layer.
 * @param  transEP         The endpoint the received data after send.
 *to.
 * @param  data             The received data buffer.
 * @return 0: success, other: failed.
 *
 **/
void SPDMRequesterImpl::msgRecvCallback(
    spdm_transport::TransportEndPoint& transEP,
    const std::vector<uint8_t>& data)
{
    addData(transEP, data);
};

/**
 * @brief Register to libspdm for receiving SPDM response payload.
 *
 * @param  spdmContext      The pointer of the spdmcontext.
 * @param  response         The response data buffer vector.
 * @param  timeout          The timeout time.
 * @return return_status defined in libspdm.
 *
 **/
return_status SPDMRequesterImpl::deviceReceiveMessage(
    void* /*spdmContext*/, std::vector<uint8_t>& response, uint64_t /*timeout*/)
{
    response = std::move(spdmResponder.data);
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("deviceReceiveMessage responseSize: " +
         std::to_string(response.size()))
            .c_str());
    return RETURN_SUCCESS;
}

/**
 * @brief Register to libspdm for sending SPDM payload.
 *
 * @param  spdmContext      The pointer of the spdmcontext.
 * @param  request          The request payload data vector.
 * @param  timeout          The timeout time.
 * @return return_status defined in libspdm.
 *
 **/
return_status
    SPDMRequesterImpl::deviceSendMessage(void* /*spdmContext*/,
                                         const std::vector<uint8_t>& request,
                                         uint64_t timeout)
{
    std::vector<uint8_t> response{};
    return_status status;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("deviceSendMessage requestSize: " + std::to_string(request.size()))
            .c_str());
    status = spdmTrans->sendRecvData(spdmResponder.transEP, request, timeout,
                                     response);
    if (!status)
    {
        addData(spdmResponder.transEP, response);
    }
    return status;
}

/**
 * @brief The authentication function
 * @return 0: success, other: failed.
 *
 **/
bool SPDMRequesterImpl::doAuthentication(void)
{
    constexpr uint8_t lastSlotIndex = 0xFF;
    uint8_t slotMask;
    uint8_t totalDigestBuffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
    uint8_t measurementHash[LIBSPDM_MAX_HASH_SIZE];
    uint32_t certChainSize;
    uint8_t certChain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

    zero_mem(totalDigestBuffer, sizeof(totalDigestBuffer));
    certChainSize = sizeof(certChain);
    zero_mem(certChain, sizeof(certChain));
    zero_mem(measurementHash, sizeof(measurementHash));
    return_status status;
    if (settingFromConfig())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDMRequesterImpl::doAuthentication starting...");
        /** Executing following functions.
            get_digest
            get_certificate
            challenge
        **/
        spdmResponder.dataCert = {};
        if ((mExeConnection & exeConnectionDigest) != 0)
        {
            status = libspdm_get_digest(spdmResponder.pspdmContext, &slotMask,
                                        totalDigestBuffer);
            if (RETURN_ERROR(status))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("SPDMRequesterImpl::doAuthentication libspdm_get_digest Error!- " +
                     std::to_string(status))
                        .c_str());
                free_pool(spdmResponder.pspdmContext);
                spdmResponder.pspdmContext = nullptr;
                return false;
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "SPDMRequesterImpl::doAuthentication libspdm_get_digest completed!");
            }
        }
        if ((mExeConnection & exeConnectionCert) != 0)
        {
            if (useSlotId != lastSlotIndex)
            {
                status = libspdm_get_certificate(spdmResponder.pspdmContext,
                                                 useSlotId, &certChainSize,
                                                 certChain);
                if (RETURN_ERROR(status))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("SPDMRequesterImpl::doAuthentication libspdm_get_certificate Error! - " +
                         std::to_string(status))
                            .c_str());
                    free_pool(spdmResponder.pspdmContext);
                    spdmResponder.pspdmContext = nullptr;
                    spdmResponder.dataCert = {};
                    return false;
                }
                else
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "SPDMRequesterImpl::doAuthentication libspdm_get_certificate completed!");
                    // Keep certificate to reserved vector.
                    if (spdmResponder.dataCert.size() == 0)
                    {
                        spdmResponder.dataCert.insert(
                            spdmResponder.dataCert.end(), certChain,
                            certChain + certChainSize);
                    }
                }
            }
        }
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDMRequesterImpl::doAuthentication Pass!!");
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::doAuthentication responder setting error!");
        return false;
    }

    return true;
}

/**
 * @brief The measurement function
 *
 * @param  sessionid          The session id pointer(reserved for further
 *use).
 * @return 0: success, other: failed.
 *
 **/
bool SPDMRequesterImpl::doMeasurement(const uint32_t* session_id)
{
    constexpr uint8_t lastBlockIndex = 0xFE;
    return_status status;
    uint8_t numberOfBlocks;
    uint8_t numberOfBlock;
    uint8_t receivedNumberOfBlock;
    uint32_t measurementRecordLength;
    uint8_t measurementRecord[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t measurementHash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t index;
    uint8_t requestAttribute;

    zero_mem(measurementHash, sizeof(measurementHash));
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Requesting all the Measurements.");
    if (spdmResponder.pspdmContext != nullptr && doAuthentication())
    {
        if ((mExeConnection & exeConnectionChal) != 0)
        {
            status = libspdm_challenge(spdmResponder.pspdmContext, useSlotId,
                                       mUseMeasurementSummaryHashType,
                                       measurementHash, nullptr);
            if (RETURN_ERROR(status))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("SPDMRequesterImpl::doAuthentication libspdm_challenge Error! - " +
                     std::to_string(status))
                        .c_str());
                free_pool(spdmResponder.pspdmContext);
                spdmResponder.pspdmContext = nullptr;
                return false;
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "SPDMRequesterImpl::doAuthentication libspdm_challenge completed!");
            }
        }

        if (mUseMeasurementOperation ==
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS)
        {
            /* request all at one time.*/
            spdmResponder.dataMeas = {};
            requestAttribute =
                SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
            measurementRecordLength = sizeof(measurementRecord);
            status = libspdm_get_measurement(
                spdmResponder.pspdmContext, session_id, requestAttribute,
                SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
                useSlotId & 0xF, nullptr, &numberOfBlock,
                &measurementRecordLength, measurementRecord);
            if (RETURN_ERROR(status))
            {
                spdmResponder.dataMeas = {};
                return false;
            }
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("SPDMRequesterImpl::doMeasurement numberOfBlock - " +
                 std::to_string(numberOfBlock))
                    .c_str());
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("SPDMRequesterImpl::doMeasurement measurementRecordLength - " +
                 std::to_string(measurementRecordLength))
                    .c_str());
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "SPDMRequesterImpl::doMeasurement Reset measurement vector.");
            // Keep measurement to reserved vector.
            spdmResponder.dataMeas = {};

            spdmResponder.dataMeas.insert(
                spdmResponder.dataMeas.end(), measurementRecord,
                measurementRecord + measurementRecordLength);
        }
        else
        {
            requestAttribute = mUseMeasurementAttribute;

            /* 1. query the total number of measurements available.*/

            status = libspdm_get_measurement(
                spdmResponder.pspdmContext, session_id, requestAttribute,
                SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
                useSlotId & 0xF, nullptr, &numberOfBlocks, nullptr, nullptr);
            spdmResponder.dataMeas = {};
            if (RETURN_ERROR(status))
            {
                return false;
            }
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("SPDMRequesterImpl::doMeasurement numberOfBlock - " +
                 std::to_string(numberOfBlock))
                    .c_str());
            receivedNumberOfBlock = 0;
            for (index = 1; index <= lastBlockIndex; index++)
            {
                if (receivedNumberOfBlock == numberOfBlocks)
                {
                    break;
                }
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("SPDMRequesterImpl::doMeasurement index - " +
                     std::to_string(index))
                        .c_str());

                /* 2. query measurement one by one*/
                /* get signature in last message only.*/

                if (receivedNumberOfBlock == numberOfBlocks - 1)
                {
                    requestAttribute =
                        mUseMeasurementAttribute |
                        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
                }
                measurementRecordLength = sizeof(measurementRecord);
                status = libspdm_get_measurement(
                    spdmResponder.pspdmContext, session_id, requestAttribute,
                    index, useSlotId & 0xF, nullptr, &numberOfBlock,
                    &measurementRecordLength, measurementRecord);
                if (RETURN_ERROR(status))
                {
                    continue;
                }
                receivedNumberOfBlock += 1;
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("SPDMRequesterImpl::doMeasurement measurementRecordLength - " +
                     std::to_string(measurementRecordLength))
                        .c_str());
                // Keep measurement to reserved vector.

                spdmResponder.dataMeas.insert(
                    spdmResponder.dataMeas.end(), measurementRecord,
                    measurementRecord + measurementRecordLength);
            }
            if (receivedNumberOfBlock != numberOfBlocks)
            {
                spdmResponder.dataMeas = {};
                return false;
            }
        }
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDMRequesterImpl::doMeasurement PASS!!");
        return true;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::doMeasurement Error!");
        return false;
    }
}

/**
 * @brief Get all measurement function
 *
 * The doMeasurement should be executed  successfully before calling this
 *function.
 * @return vector of all measurements.
 **/
bool SPDMRequesterImpl::getMeasurements(std::vector<uint8_t>& meaurements)
{
    if (doMeasurement(NULL) && !spdmResponder.dataMeas.empty())
    {
        meaurements = spdmResponder.dataMeas;
        spdmResponder.dataMeas.clear();
        return true;
    }
    return false;
}

/**
 * @brief Get certification function
 *
 * The doAuthentication should be executed  successfully before calling this
 *function.
 * @return vector of certification.
 **/
bool SPDMRequesterImpl::getCertificate(std::vector<uint8_t>& certificate)
{
    if (doAuthentication() && !spdmResponder.dataCert.empty())
    {
        certificate = spdmResponder.dataCert;
        spdmResponder.dataCert.clear();
        return true;
    }
    return false;
}

/**
 * @brief Constructor of SPDM requester
 *
 * @param  ioc               The shared_ptr to boost io_context object.
 * @param  conn              sdbusplus connection
 * @param  trans             The pointer of transport instance.
 * @param  endPoint          Assigned responder EndPoint.
 * @param  spdmConfig        User input SPDMConfiguration.
 **/
SPDMRequesterImpl::SPDMRequesterImpl(
    std::shared_ptr<boost::asio::io_context> io,
    std::shared_ptr<sdbusplus::asio::connection> con,
    std::shared_ptr<spdm_transport::SPDMTransport> trans,
    spdm_transport::TransportEndPoint& endPointDevice,
    SPDMConfiguration& pSpdmConfig) :
    ioc(io),
    conn(con), spdmTrans(trans), transResponder(endPointDevice),
    spdmRequesterCfg(pSpdmConfig)
{
    if (spdmRequesterCfg.version)
    {
        setCertificatePath(spdmRequesterCfg.certPath);

        mExeConnection = (0 | exeConnectionDigest | exeConnectionCert |
                          exeConnectionChal | exeConnectionMeas);

        if (!setupResponder(transResponder))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "SPDMRequesterImpl init set up failed!");
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl getConfigurationFromEntityManager failed!");
    }
}

} // namespace spdm_app_lib
