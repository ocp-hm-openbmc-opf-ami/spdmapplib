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
    return pspdmTmp->deviceSendMessage(spdmContext, requestSize, request,
                                       timeout);
}

return_status requesterDeviceReceiveMessage(void* spdmContext,
                                            uintn* responseSize, void* response,
                                            uint64_t timeout)
{
    void* pTmp = NULL;
    spdmRequesterImpl* pspdmTmp = NULL;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == NULL)
        return false;
    pspdmTmp = static_cast<spdmRequesterImpl*>(pTmp);
    return pspdmTmp->deviceReceiveMessage(spdmContext, responseSize, response,
                                          timeout);
}

/**
 * @brief Initial function of SPDM requester
 *
 * @param  io                boost io_service object..
 * @param  trans             The pointer of transport instance.
 * @param  ptransResponder   The pointer to assigned responder EndPoint.
 * @param  pSpdmConfig       The pointer to a spdmConfiguration structure.
 * @return 0: success, other: listed in spdmapplib::errorCodes
 **/
int spdmRequesterImpl::initRequester(
    std::shared_ptr<boost::asio::io_service> io,
    std::shared_ptr<sdbusplus::asio::connection> conn,
    std::shared_ptr<spdmtransport::spdmTransport> trans,
    spdmtransport::transportEndPoint* ptransResponder,
    spdmConfiguration* pSpdmConfig)
{
    using namespace std::placeholders;
    spdmtransport::transportEndPoint* pTmp;
    int intResult = -1;
    bResponderFound = false; // init member variable.
    pio = io;
    spdmRequesterCfg = *pSpdmConfig;
    if (spdmRequesterCfg.version)
    {
        if (setCertificatePath(spdmRequesterCfg.certPath) == false)
        {
            return -1;
        }
        m_exe_connection = (0 | EXE_CONNECTION_DIGEST | EXE_CONNECTION_CERT |
                            EXE_CONNECTION_CHAL | EXE_CONNECTION_MEAS | 0);
        pTmp = static_cast<spdmtransport::transportEndPoint*>(&transResponder);
        spdmTrans = trans;
        if (copyDevice(pTmp, ptransResponder))
        {
            intResult = setupResponder(pTmp);
            if (intResult == 0)
            {
                spdmTrans->initTransport(
                    io, conn,
                    std::bind(&spdmRequesterImpl::checkResponderDevice, this,
                              _1),
                    NULL,
                    std::bind(&spdmRequesterImpl::MsgRecvCallback, this, _1,
                              _2));
            }
            phosphor::logging::log<phosphor::logging::level::INFO>(
                ("spdmRequesterImpl::initRequester intResult: " +
                 std::to_string(intResult) +
                 ", bResponderFound: " + std::to_string(bResponderFound))
                    .c_str());
        }
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
int spdmRequesterImpl::checkResponderDevice(void* ptransEP)
{
    if (ptransEP == NULL)
    {
        return false;
    }
    if (matchDevice(&spdmResponder.transEP,
                    static_cast<spdmtransport::transportEndPoint*>(ptransEP)))
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
    uint8_t u8Value;   // Value that size is uint8_t
    uint16_t u16Value; // Value that size is uint16_t
    uint32_t u32Value; // Value that size is uint32_t
    void* tmpThis = static_cast<void*>(this);
    return_status status;

    uintn data_size;
    useSlotCount = static_cast<uint8_t>(spdmRequesterCfg.slotcount);
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("spdmRequesterImpl::settingFromConfig Requester useSlotCount: " +
         std::to_string(spdmRequesterCfg.slotcount))
            .c_str());

    useSlotId = 0;
    m_use_measurement_summary_hash_type =
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
    m_use_measurement_operation =
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
    m_use_measurement_attribute = 0;

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
    m_use_asym_algo = spdmRequesterCfg.asym;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u16Value = (uint16_t)spdmRequesterCfg.reqasym;
    m_use_req_asym_algo = (uint16_t)spdmRequesterCfg.reqasym;
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }

    u32Value = spdmRequesterCfg.hash;
    m_use_hash_algo = spdmRequesterCfg.hash;
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
    m_use_asym_algo = u32Value;
    data_size = sizeof(u32Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                              &u32Value, &data_size);
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }
    m_use_hash_algo = u32Value;
    data_size = sizeof(u16Value);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                              &u16Value, &data_size);
    if (RETURN_ERROR(status))
    {
        return static_cast<int>(errorCodes::libspdmReturnError);
    }
    m_use_req_asym_algo = u16Value;

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("spdmRequesterImpl::settingFromConfig m_use_asym_algo: " +
         std::to_string(m_use_asym_algo))
            .c_str());
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("spdmRequesterImpl::settingFromConfig m_use_hash_algo: " +
         std::to_string(m_use_hash_algo))
            .c_str());
    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("spdmRequesterImpl::settingFromConfig m_use_req_asym_algo: " +
         std::to_string(m_use_req_asym_algo))
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
int spdmRequesterImpl::setupResponder(
    spdmtransport::transportEndPoint* ptransEP)
{
    return_status status;
    spdmResponder.pspdmContext = (void*)malloc(libspdm_get_context_size());
    if (spdmResponder.pspdmContext == NULL)
    {
        return -1;
    }
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "spdmRequesterImpl::setupResponder");
    copyDevice(&spdmResponder.transEP, ptransEP);
    spdmResponder.useSlotId = 0;
    spdmResponder.sessonId = 0;
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
 * @param  ptransEP          Endpoint object pointer.
 * @param  trans             The pointer of transport instance.
 * @return 0: success, other: failed.
 *
 **/
int spdmRequesterImpl::addData(void* ptransEP, const std::vector<uint8_t>& data)
{
    if (matchDevice(&spdmResponder.transEP,
                    static_cast<spdmtransport::transportEndPoint*>(ptransEP)))
    {
        spdmResponder.data = data;
        return RETURN_SUCCESS;
    }
    return false;
}

/**
 * @brief Function to pass as parameter of syncSendRecvData of transport
 *layer.
 *
 *  The function will be called when send/receive is completed in transport
 *layer.
 * @param  ptransEP         Pointer to the endpoint the received data send
 *to.
 * @param  data             The received data buffer.
 * @return 0: success, other: failed.
 *
 **/
int spdmRequesterImpl::MsgRecvCallback(void* ptransEP,
                                       const std::vector<uint8_t>& data)
{
    addData(ptransEP, data);
    return RETURN_SUCCESS;
};

/**
 * @brief Register to libspdm for receiving SPDM response payload.
 *
 * @param  spdmContext      The pointer of the spdmcontext.
 * @param  responseSize     The variable pointer for received data size.
 * @param  response         The response data buffer pointer.
 * @param  timeout          The timeout time.
 * @return return_status defined in libspdm.
 *
 **/
return_status spdmRequesterImpl::deviceReceiveMessage(void* /*spdmContext*/,
                                                      uintn* responseSize,
                                                      void* response,
                                                      uint64_t /*timeout*/)
{
    *responseSize = spdmResponder.data.size() - 1;
    std::copy(spdmResponder.data.begin() + 1, spdmResponder.data.end(),
              (uint8_t*)response);
    spdmResponder.data.clear();
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("deviceReceiveMessage responseSize: " + std::to_string(*responseSize))
            .c_str());
    return RETURN_SUCCESS;
}

/**
 * @brief Register to libspdm for sending SPDM payload.
 *
 * @param  spdmContext      The pointer of the spdmcontext.
 * @param  requestSize      The request payload size.
 * @param  request          The request payload data buffer.
 * @param  timeout          The timeout time.
 * @return return_status defined in libspdm.
 *
 **/
return_status spdmRequesterImpl::deviceSendMessage(void* /*spdmContext*/,
                                                   uintn requestSize,
                                                   const void* request,
                                                   uint64_t timeout)
{
    using namespace std::placeholders;
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("deviceSendMessage requestSize: " + std::to_string(requestSize))
            .c_str());
    return spdmTrans->syncSendRecvData(
        &spdmResponder.transEP, requestSize, request, timeout,
        std::bind(&spdmRequesterImpl::MsgRecvCallback, this, _1, _2));
}

/**
 * @brief The authentication function
 * @return 0: success, other: failed.
 *
 **/
int spdmRequesterImpl::do_authentication(void)
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
                "spdmRequesterImpl::do_authentication starting...");
            /** Executing following functions.
                get_digest
                get_certificate
                challenge
            **/
            if ((m_exe_connection & EXE_CONNECTION_DIGEST) != 0)
            {
                status = libspdm_get_digest(spdmResponder.pspdmContext,
                                            &slot_mask, total_digest_buffer);
                if (RETURN_ERROR(status))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("spdmRequesterImpl::do_authentication libspdm_get_digest Error!- " +
                         std::to_string(status))
                            .c_str());
                    free(spdmResponder.pspdmContext);
                    spdmResponder.pspdmContext = NULL;
                    return status;
                }
                else
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "spdmRequesterImpl::do_authentication libspdm_get_digest completed!");
                }
            }

            if ((m_exe_connection & EXE_CONNECTION_CERT) != 0)
            {
                if (useSlotId != 0xFF)
                {
                    status = libspdm_get_certificate(
                        spdmResponder.pspdmContext, useSlotId, &cert_chain_size,
                        cert_chain);
                    if (RETURN_ERROR(status))
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            ("spdmRequesterImpl::do_authentication libspdm_get_certificate Error! - " +
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
                            "spdmRequesterImpl::do_authentication libspdm_get_certificate completed!");
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

            if ((m_exe_connection & EXE_CONNECTION_CHAL) != 0)
            {
                status =
                    libspdm_challenge(spdmResponder.pspdmContext, useSlotId,
                                      m_use_measurement_summary_hash_type,
                                      measurement_hash, NULL);
                if (RETURN_ERROR(status))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("spdmRequesterImpl::do_authentication libspdm_challenge Error! - " +
                         std::to_string(status))
                            .c_str());
                    free(spdmResponder.pspdmContext);
                    spdmResponder.pspdmContext = NULL;
                    return status;
                }
                else
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "spdmRequesterImpl::do_authentication libspdm_challenge completed!");
                }
            }
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "spdmRequesterImpl::do_authentication Pass!!");
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "spdmRequesterImpl::do_authentication responder setting error!");
            return -1;
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "spdmRequesterImpl::do_authentication responder not found yet!");
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
int spdmRequesterImpl::do_measurement(const uint32_t* session_id)
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
        "Requesting all the Measurements in do_measurement!!");
    if (bResponderFound && (spdmResponder.pspdmContext != NULL))
    {
        if (m_use_measurement_operation ==
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
                ("spdmRequesterImpl::do_measurement number_of_block - " +
                 std::to_string(number_of_block))
                    .c_str());
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                ("spdmRequesterImpl::do_measurement measurement_record_length - " +
                 std::to_string(measurement_record_length))
                    .c_str());
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "spdmRequesterImpl::do_measurement Reset measurement vector.");
            // Keep measurement to reserved vector.
            spdmResponder.dataMeas = {};

            spdmResponder.dataMeas.insert(
                spdmResponder.dataMeas.end(), measurement_record,
                measurement_record + measurement_record_length);
        }
        else
        {
            request_attribute = m_use_measurement_attribute;

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
                ("spdmRequesterImpl::do_measurement number_of_block - " +
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
                    ("spdmRequesterImpl::do_measurement index - " +
                     std::to_string(index))
                        .c_str());

                /* 2. query measurement one by one*/
                /* get signature in last message only.*/

                if (received_number_of_block == number_of_blocks - 1)
                {
                    request_attribute =
                        m_use_measurement_attribute |
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
                    ("spdmRequesterImpl::do_measurement measurement_record_length - " +
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
            "spdmRequesterImpl::do_measurement PASS!!");
        return RETURN_SUCCESS;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "spdmRequesterImpl::do_measurement Error!");
        return -1;
    }
}

/**
 * @brief Get all measurement function
 *
 * The do_measurement should be executed  successfully before calling this
 *function.
 * @return vector of all measurements.
 **/
std::optional<std::vector<uint8_t>> spdmRequesterImpl::get_measurements()
{
    return spdmResponder.dataMeas;
}

/**
 * @brief Get certification function
 *
 * The do_authentication should be executed  successfully before calling this
 *function.
 * @return vector of certification.
 **/
std::optional<std::vector<uint8_t>> spdmRequesterImpl::get_certificate()
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
