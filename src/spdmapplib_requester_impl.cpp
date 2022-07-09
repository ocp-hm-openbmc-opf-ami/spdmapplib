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

namespace spdmapplib
{
/*Callback functions for libspdm */

return_status requesterDeviceSendMessage(void* spdmContext, uintn requestSize,
                                         const void* request, uint64_t timeout)
{
    void* pTmp = NULL;
    spdmRequesterImpl* pspdmTmp = NULL;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == NULL)
        return false;
    pspdmTmp = static_cast<spdmRequesterImpl*>(pTmp);

    uint32_t j;
    std::vector<uint8_t> data;

    uint8_t* requestPayload = (uint8_t*)request;

    data.push_back(static_cast<uint8_t>(mctpw::MessageType::spdm));

    for (j = 0; j < requestSize; j++)
        data.push_back(*(requestPayload + j));

    return pspdmTmp->deviceSendMessage(spdmContext, data, timeout);
}

return_status requesterDeviceReceiveMessage(void* spdmContext,
                                            uintn* responseSize, void* response,
                                            uint64_t timeout)
{
    void* pTmp = NULL;
    return_status status;
    spdmRequesterImpl* pspdmTmp = NULL;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == NULL)
        return false;
    pspdmTmp = static_cast<spdmRequesterImpl*>(pTmp);
    std::vector<uint8_t> rspData{};
    status = pspdmTmp->deviceReceiveMessage(spdmContext, rspData, timeout);
    *responseSize = rspData.size() - 1; // skip MessageType byte
    std::copy(rspData.begin() + 1, rspData.end(), (uint8_t*)response);
    return status;
}

/**
 * @brief Initial function of SPDM requester
 *
 * @param  io                boost io_service object..
 * @param  trans             The pointer of transport instance.
 * @param  cfgTransResponder Assigned responder EndPoint.
 * @param  spdmConfig        User input SpdmConfiguration.
 * @return 0: success, other: listed in spdmapplib::errorCodes
 **/
int spdmRequesterImpl::initRequester(
    std::shared_ptr<boost::asio::io_service> io,
    std::shared_ptr<sdbusplus::asio::connection> conn,
    std::shared_ptr<spdmtransport::spdmTransport> trans,
    spdmtransport::transportEndPoint& cfgTransResponder,
    SpdmConfiguration& spdmConfig)
{
    using namespace std::placeholders;
    int intResult = -1;
    bResponderFound = false; // init member variable.
    pio = io;
    spdmRequesterCfg = spdmConfig;
    if (spdmRequesterCfg.version)
    {
        if (setCertificatePath(spdmRequesterCfg.certPath) == false)
        {
            return -1;
        }
        mExeConnection = (0 | EXE_CONNECTION_DIGEST | EXE_CONNECTION_CERT |
                          EXE_CONNECTION_CHAL | EXE_CONNECTION_MEAS | 0);
        transResponder = cfgTransResponder;
        spdmTrans = trans;
        intResult = setupResponder(transResponder);
        if (intResult == 0)
        {
            spdmTrans->initTransport(
                io, conn,
                std::bind(&spdmRequesterImpl::checkResponderDevice, this, _1),
                NULL,
                std::bind(&spdmRequesterImpl::msgRecvCallback, this, _1, _2));
        }
        phosphor::logging::log<phosphor::logging::level::INFO>(
            ("spdmRequesterImpl::initRequester intResult: " +
             std::to_string(intResult) +
             ", bResponderFound: " + std::to_string(bResponderFound))
                .c_str());
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "spdmRequesterImpl::initRequester getConfigurationFromEntityManager failed!");
        intResult = static_cast<int>(
            errorCodes::spdmConfigurationNotFoundInEntityManager);
    }
    return intResult;
}

/**
 * @brief Function to check if found endpoint is the responder assigned by
 *user.
 *
 * @param  ptransEP          Pointer of endpoint object to be checked.
 * @return 0: success, other: failed.
 *
 **/
// int spdmRequesterImpl::checkResponderDevice(void* ptransEP)
int spdmRequesterImpl::checkResponderDevice(
    spdmtransport::transportEndPoint& transEP)
{
    if (spdmResponder.transEP == transEP)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Found Responder!!");
        this->bResponderFound = true;
        return true;
    }
    return false;
}

/**
 * @brief Function to setup user assigned endpoint initial configuration.
 *
 * @return 0: success, other: failed.
 *
 **/
int spdmRequesterImpl::settingFromConfig(void)
{
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;
    uint16_t u16Value;
    uint32_t u32Value;
    void* tmpThis = static_cast<void*>(this);
    return_status status;

    uintn data_size;
    useSlotCount = static_cast<uint8_t>(spdmRequesterCfg.slotcount);
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("spdmRequesterImpl::settingFromConfig Requester useSlotCount: " +
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

    //////////////////////////////////////////////////////////////////////////////////////
    memset(&parameter, 0, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter,
                              &tmpThis, sizeof(void*));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }
    u8Value = 0;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    useRequesterCapabilityFlags = spdmRequesterCfg.capability;
    u32Value = useRequesterCapabilityFlags;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u8Value = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u32Value = spdmRequesterCfg.measHash;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u32Value = spdmRequesterCfg.asym;
    mUseAsymAlgo = spdmRequesterCfg.asym;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u16Value = (uint16_t)spdmRequesterCfg.reqasym;
    mUseReqAsymAlgo = (uint16_t)spdmRequesterCfg.reqasym;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u32Value = spdmRequesterCfg.hash;
    mUseHashAlgo = spdmRequesterCfg.hash;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u16Value = (uint16_t)spdmRequesterCfg.dhe;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u16Value = (uint16_t)spdmRequesterCfg.aead;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u16Value = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    status =
        libspdm_set_data(spdmResponder.pspdmContext, LIBSPDM_DATA_KEY_SCHEDULE,
                         &parameter, &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u8Value = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
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
            ("spdmRequesterImpl::settingFromConfig libspdm_init_connection Error!- " +
             ss.str())
                .c_str());
        free(spdmResponder.pspdmContext);
        spdmResponder.pspdmContext = NULL;
        return -1;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "spdmRequesterImpl::settingFromConfig libspdm_init_connection completed!");
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
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    data_size = sizeof(u32Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                              &u32Value, &data_size);
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("spdmRequesterImpl::settingFromConfig use measurement hash algo: " +
         std::to_string(u32Value))
            .c_str());
    data_size = sizeof(u32Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                              &u32Value, &data_size);
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }
    mUseAsymAlgo = u32Value;
    data_size = sizeof(u32Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                              &u32Value, &data_size);
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }
    mUseHashAlgo = u32Value;
    data_size = sizeof(u16Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                              &u16Value, &data_size);
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }
    mUseReqAsymAlgo = u16Value;

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("spdmRequesterImpl::settingFromConfig mUseAsymAlgo: " +
         std::to_string(mUseAsymAlgo))
            .c_str());
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("spdmRequesterImpl::settingFromConfig mUseHashAlgo: " +
         std::to_string(mUseHashAlgo))
            .c_str());
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("spdmRequesterImpl::settingFromConfig mUseReqAsymAlgo: " +
         std::to_string(mUseReqAsymAlgo))
            .c_str());

    return RETURN_SUCCESS;
}

/**
 * @brief Setup the configuration of user assigned endpoint as target
 *responder.
 *
 * @param  ptransEP          Pointer of endpoint object to be configured.
 * @return return_status defined in libspdm.
 *
 **/
int spdmRequesterImpl::setupResponder(spdmtransport::transportEndPoint& transEP)
{
    return_status status;
    spdmResponder.pspdmContext = (void*)malloc(libspdm_get_context_size());
    if (spdmResponder.pspdmContext == NULL)
    {
        return -1;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "spdmRequesterImpl::setupResponder");
    // copyDevice(&spdmResponder.transEP, ptransEP);
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
            ("spdmRequesterImpl::setupResponder libspdm_init_context failed" +
             std::to_string(status))
                .c_str());
        return -1;
    }
    libspdm_register_device_io_func(spdmResponder.pspdmContext,
                                    requesterDeviceSendMessage,
                                    requesterDeviceReceiveMessage);

    libspdm_register_transport_layer_func(spdmResponder.pspdmContext,
                                          spdm_transport_none_encode_message,
                                          spdm_transport_none_decode_message);

    return RETURN_SUCCESS;
}

/**
 * @brief Set received data to assigned endpoint.
 *
 * @param  transEP          The Endpoint object to receive data.
 * @param  trans             The pointer of transport instance.
 * @return 0: success, other: failed.
 *
 **/
int spdmRequesterImpl::addData(spdmtransport::transportEndPoint& transEP,
                               const std::vector<uint8_t>& data)
{
    if (spdmResponder.transEP == transEP)
    {
        spdmResponder.data = data;
        return RETURN_SUCCESS;
    }
    return -1;
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
int spdmRequesterImpl::msgRecvCallback(
    spdmtransport::transportEndPoint& transEP, const std::vector<uint8_t>& data)
{
    addData(transEP, data);
    return RETURN_SUCCESS;
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
return_status spdmRequesterImpl::deviceReceiveMessage(
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
    spdmRequesterImpl::deviceSendMessage(void* /*spdmContext*/,
                                         const std::vector<uint8_t>& request,
                                         uint64_t timeout)
{
    using namespace std::placeholders;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("deviceSendMessage requestSize: " + std::to_string(request.size()))
            .c_str());
    return spdmTrans->syncSendRecvData(
        spdmResponder.transEP, request, timeout,
        std::bind(&spdmRequesterImpl::msgRecvCallback, this, _1, _2));
}

/**
 * @brief The authentication function
 * @return 0: success, other: failed.
 *
 **/
int spdmRequesterImpl::doAuthentication(void)
{
    if (bResponderFound)
    {
        uint8_t slot_mask;
        uint8_t
            total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
        uint8_t measurement_hash[LIBSPDM_MAX_HASH_SIZE];
        uintn cert_chain_size;
        uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];

        zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
        cert_chain_size = sizeof(cert_chain);
        zero_mem(cert_chain, sizeof(cert_chain));
        zero_mem(measurement_hash, sizeof(measurement_hash));
        return_status status;
        if (settingFromConfig() == RETURN_SUCCESS)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "spdmRequesterImpl::doAuthentication starting...");
            /** Executing following functions.
                get_digest
                get_certificate
                challenge
            **/
            if ((mExeConnection & EXE_CONNECTION_DIGEST) != 0)
            {
                status = libspdm_get_digest(spdmResponder.pspdmContext,
                                            &slot_mask, total_digest_buffer);
                if (RETURN_ERROR(status))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("spdmRequesterImpl::doAuthentication libspdm_get_digest Error!- " +
                         std::to_string(status))
                            .c_str());
                    free(spdmResponder.pspdmContext);
                    spdmResponder.pspdmContext = NULL;
                    return status;
                }
                else
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "spdmRequesterImpl::doAuthentication libspdm_get_digest completed!");
                }
            }

            if ((mExeConnection & EXE_CONNECTION_CERT) != 0)
            {
                if (useSlotId != 0xFF)
                {
                    status = libspdm_get_certificate(
                        spdmResponder.pspdmContext, useSlotId, &cert_chain_size,
                        cert_chain);
                    if (RETURN_ERROR(status))
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            ("spdmRequesterImpl::doAuthentication libspdm_get_certificate Error! - " +
                             std::to_string(status))
                                .c_str());
                        free(spdmResponder.pspdmContext);
                        spdmResponder.pspdmContext = NULL;
                        spdmResponder.dataCert = {};
                        return status;
                    }
                    else
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            "spdmRequesterImpl::doAuthentication libspdm_get_certificate completed!");
                        // Keep certificate to reserved vector.
                        if (spdmResponder.dataCert.size() == 0)
                        {
                            spdmResponder.dataCert.insert(
                                spdmResponder.dataCert.end(), cert_chain,
                                cert_chain + cert_chain_size);
                        }
                    }
                }
            }

            if ((mExeConnection & EXE_CONNECTION_CHAL) != 0)
            {
                status = libspdm_challenge(
                    spdmResponder.pspdmContext, useSlotId,
                    mUseMeasurementSummaryHashType, measurement_hash, NULL);
                if (RETURN_ERROR(status))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("spdmRequesterImpl::doAuthentication libspdm_challenge Error! - " +
                         std::to_string(status))
                            .c_str());
                    free(spdmResponder.pspdmContext);
                    spdmResponder.pspdmContext = NULL;
                    return status;
                }
                else
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "spdmRequesterImpl::doAuthentication libspdm_challenge completed!");
                }
            }
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "spdmRequesterImpl::doAuthentication Pass!!");
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "spdmRequesterImpl::doAuthentication responder setting error!");
            return -1;
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "spdmRequesterImpl::doAuthentication responder not found yet!");
        return -1;
    }
    return RETURN_SUCCESS;
}

/**
 * @brief The measurement function
 *
 * @param  sessionid          The session id pointer(reserved for further
 *use).
 * @return 0: success, other: failed.
 *
 **/
int spdmRequesterImpl::doMeasurement(const uint32_t* session_id)
{
    return_status status;
    uint8_t number_of_blocks;
    uint8_t number_of_block;
    uint8_t received_number_of_block;
    uint32_t measurement_record_length;
    uint8_t measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t index;
    uint8_t request_attribute;

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Requesting all the Measurements.");
    if (bResponderFound && (spdmResponder.pspdmContext != NULL))
    {
        if (mUseMeasurementOperation ==
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS)
        {
            /* request all at one time.*/

            request_attribute =
                SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
            measurement_record_length = sizeof(measurement_record);
            status = libspdm_get_measurement(
                spdmResponder.pspdmContext, session_id, request_attribute,
                SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
                useSlotId & 0xF, NULL, &number_of_block,
                &measurement_record_length, measurement_record);
            if (RETURN_ERROR(status))
            {
                spdmResponder.dataMeas = {};
                return status;
            }
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("spdmRequesterImpl::doMeasurement number_of_block - " +
                 std::to_string(number_of_block))
                    .c_str());
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("spdmRequesterImpl::doMeasurement measurement_record_length - " +
                 std::to_string(measurement_record_length))
                    .c_str());
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "spdmRequesterImpl::doMeasurement Reset measurement vector.");
            // Keep measurement to reserved vector.
            spdmResponder.dataMeas = {};

            spdmResponder.dataMeas.insert(
                spdmResponder.dataMeas.end(), measurement_record,
                measurement_record + measurement_record_length);
        }
        else
        {
            request_attribute = mUseMeasurementAttribute;

            /* 1. query the total number of measurements available.*/

            status = libspdm_get_measurement(
                spdmResponder.pspdmContext, session_id, request_attribute,
                SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
                useSlotId & 0xF, NULL, &number_of_blocks, NULL, NULL);
            spdmResponder.dataMeas = {};
            if (RETURN_ERROR(status))
            {
                return status;
            }
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("spdmRequesterImpl::doMeasurement number_of_block - " +
                 std::to_string(number_of_block))
                    .c_str());
            received_number_of_block = 0;
            for (index = 1; index <= 0xFE; index++)
            {
                if (received_number_of_block == number_of_blocks)
                {
                    break;
                }
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("spdmRequesterImpl::doMeasurement index - " +
                     std::to_string(index))
                        .c_str());

                /* 2. query measurement one by one*/
                /* get signature in last message only.*/

                if (received_number_of_block == number_of_blocks - 1)
                {
                    request_attribute =
                        mUseMeasurementAttribute |
                        SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
                }
                measurement_record_length = sizeof(measurement_record);
                status = libspdm_get_measurement(
                    spdmResponder.pspdmContext, session_id, request_attribute,
                    index, useSlotId & 0xF, NULL, &number_of_block,
                    &measurement_record_length, measurement_record);
                if (RETURN_ERROR(status))
                {
                    continue;
                }
                received_number_of_block += 1;
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    ("spdmRequesterImpl::doMeasurement measurement_record_length - " +
                     std::to_string(measurement_record_length))
                        .c_str());
                // Keep measurement to reserved vector.

                spdmResponder.dataMeas.insert(
                    spdmResponder.dataMeas.end(), measurement_record,
                    measurement_record + measurement_record_length);
            }
            if (received_number_of_block != number_of_blocks)
            {
                spdmResponder.dataMeas = {};
                return RETURN_DEVICE_ERROR;
            }
        }
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "spdmRequesterImpl::doMeasurement PASS!!");
        return RETURN_SUCCESS;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "spdmRequesterImpl::doMeasurement Error!");
        return -1;
    }
}

/**
 * @brief Get all measurement function
 *
 * The doMeasurement should be executed  successfully before calling this
 *function.
 * @return vector of all measurements.
 **/
std::optional<std::vector<uint8_t>> spdmRequesterImpl::getMeasurements()
{
    return spdmResponder.dataMeas;
}

/**
 * @brief Get certification function
 *
 * The doAuthentication should be executed  successfully before calling this
 *function.
 * @return vector of certification.
 **/
std::optional<std::vector<uint8_t>> spdmRequesterImpl::getCertificate()
{
    return spdmResponder.dataCert;
}

/**
 * @brief Requester object create Factory function.
 *
 * @return Pointer to Requester implementation object.
 *
 **/

std::shared_ptr<spdmRequester> createRequester()
{
    return std::make_shared<spdmRequesterImpl>();
}

} // namespace spdmapplib
