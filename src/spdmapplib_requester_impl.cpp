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
#include "spdmapplib_requester_impl.hpp"

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
    return_status status;
    uint32_t dataSize = 0;
    void* spdmAppContext = nullptr;
    libspdm_data_parameter_t parameter;

    dataSize = sizeof(spdmAppContext);
    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    status = libspdm_get_data(spdmContext, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              &parameter, &spdmAppContext, &dataSize);
    if (RETURN_ERROR(status))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    SPDMRequesterImpl* pspdmTmp =
        reinterpret_cast<SPDMRequesterImpl*>(spdmAppContext);
    uint8_t* requestPayload = (uint8_t*)(request);
    std::vector<uint8_t> data{};
    data.push_back(static_cast<uint8_t>(mctpw::MessageType::spdm));
    for (uint32_t j = 0; j < requestSize; j++)
    {
        data.push_back(*(requestPayload + j));
    }
    return pspdmTmp->deviceSendMessage(spdmContext, data, timeout);
}

return_status requesterDeviceReceiveMessage(void* spdmContext,
                                            uintn* responseSize, void* response,
                                            uint64_t timeout)
{
    return_status status;
    uint32_t dataSize = 0;
    void* spdmAppContext = nullptr;
    libspdm_data_parameter_t parameter;

    dataSize = sizeof(spdmAppContext);
    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    status = libspdm_get_data(spdmContext, LIBSPDM_DATA_APP_CONTEXT_DATA,
                              &parameter, &spdmAppContext, &dataSize);
    if (RETURN_ERROR(status))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    SPDMRequesterImpl* pspdmTmp =
        reinterpret_cast<SPDMRequesterImpl*>(spdmAppContext);
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

bool SPDMRequesterImpl::settingFromConfig(void)
{
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;
    uint16_t u16Value;
    uint32_t u32Value;
    void* tmpThis = static_cast<void*>(this);
    return_status status;

    phosphor::logging::log<phosphor::logging::level::INFO>(
        ("SPDMRequesterImpl::settingFromConfig Requester useSlotCount: " +
         std::to_string(spdmRequesterCfg.slotcount))
            .c_str());

    mUseMeasurementOperation =
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
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

    u32Value = spdmRequesterCfg.capability;
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
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u16Value = static_cast<uint16_t>(spdmRequesterCfg.reqasym);
    status = libspdm_set_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u32Value = spdmRequesterCfg.hash;
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
    return true;
}

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

void SPDMRequesterImpl::addData(spdm_transport::TransportEndPoint& transEP,
                                const std::vector<uint8_t>& data)
{
    if (spdmResponder.transEP == transEP)
    {
        spdmResponder.data = std::move(data);
    }
}

void SPDMRequesterImpl::msgRecvCallback(
    spdm_transport::TransportEndPoint& transEP,
    const std::vector<uint8_t>& data)
{
    addData(transEP, data);
};

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

return_status
    SPDMRequesterImpl::deviceSendMessage(void* /*spdmContext*/,
                                         const std::vector<uint8_t>& request,
                                         uint64_t timeout)
{
    return_status status;
    std::vector<uint8_t> response{};
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

bool SPDMRequesterImpl::doAuthentication(void)
{
    return_status status;
    uint8_t slotMask = 0;
    uint8_t useSlotId = 0;
    uint32_t certChainSize = 0;
    constexpr uint8_t lastSlotIndex = 0xFF;
    std::array<uint8_t, LIBSPDM_MAX_CERT_CHAIN_SIZE> certChain{0};
    std::array<uint8_t, LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT>
        totalDigestBuffer{0};
    spdmResponder.dataCert.clear();
    certChainSize = certChain.size();

    if (!getVCA(false))
    {
        return false;
    }

    if (!isConnStateNegotiated())
    {
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "SPDMRequesterImpl::doAuthentication starting...");
    /** Executing following functions.
        get_digest
        get_certificate
        challenge
    **/
    if ((exeConnection & exeConnectionDigest) != 0)
    {
        status = libspdm_get_digest(spdmResponder.pspdmContext, &slotMask,
                                    &totalDigestBuffer);
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
    if ((exeConnection & exeConnectionCert) != 0)
    {
        if (useSlotId != lastSlotIndex)
        {
            status =
                libspdm_get_certificate(spdmResponder.pspdmContext, useSlotId,
                                        &certChainSize, &certChain);
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
                        spdmResponder.dataCert.end(), certChain.begin(),
                        certChain.begin() + certChainSize);
                }
            }
        }
    }
    return true;
}

bool SPDMRequesterImpl::doMeasurement(const uint32_t* session_id)
{
    uint8_t index = 0;
    return_status status;
    uint8_t useSlotId = 0;
    uint8_t numberOfBlock = 0;
    uint8_t numberOfBlocks = 0;
    uint8_t requestAttribute = 0;
    uint8_t receivedNumberOfBlock = 0;
    uint8_t mUseMeasurementAttribute = 0;
    uint32_t measurementRecordLength = 0;
    constexpr uint8_t lastBlockIndex = 0xFE;
    std::array<uint8_t, LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE> measurementRecord{
        0};
    std::array<uint8_t, LIBSPDM_MAX_HASH_SIZE> measurementHash{0};
    spdmResponder.dataMeas.clear();

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "Requesting all the Measurements.");
    if (spdmResponder.pspdmContext == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::doMeasurement Error!");
        return false;
    }
    if (spdmResponder.dataCert.empty())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "SPDMRequesterImpl::doMeasurement doAuthentication()");
        doAuthentication();
    }

    if ((exeConnection & exeConnectionChal) != 0)
    {
        status = libspdm_challenge(spdmResponder.pspdmContext, useSlotId,
                                   SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH,
                                   &measurementHash, nullptr);
        if (RETURN_ERROR(status))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("SPDMRequesterImpl::doMeasurement libspdm_challenge Error! - " +
                 std::to_string(status))
                    .c_str());
            free_pool(spdmResponder.pspdmContext);
            spdmResponder.pspdmContext = nullptr;
            return false;
        }
    }

    if (mUseMeasurementOperation ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS)
    {
        /* request all at one time.*/
        requestAttribute =
            SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        measurementRecordLength = measurementRecord.size();
        status = libspdm_get_measurement(
            spdmResponder.pspdmContext, session_id, requestAttribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
            useSlotId & 0xF, nullptr, &numberOfBlock, &measurementRecordLength,
            &measurementRecord);
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
        spdmResponder.dataMeas.insert(
            spdmResponder.dataMeas.end(), measurementRecord.begin(),
            measurementRecord.begin() + measurementRecordLength);
    }
    else
    {
        requestAttribute = mUseMeasurementAttribute;
        /* 1. query the total number of measurements available.*/
        status = libspdm_get_measurement(
            spdmResponder.pspdmContext, session_id, requestAttribute,
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
            useSlotId & 0xF, nullptr, &numberOfBlocks, nullptr, nullptr);
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
                spdmResponder.pspdmContext, session_id, requestAttribute, index,
                useSlotId & 0xF, nullptr, &numberOfBlock,
                &measurementRecordLength, &measurementRecord);
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
                spdmResponder.dataMeas.end(), measurementRecord.begin(),
                measurementRecord.begin() + measurementRecordLength);
        }
        if (receivedNumberOfBlock != numberOfBlocks)
        {
            spdmResponder.dataMeas.clear();
            return false;
        }
    }
    return true;
}

bool SPDMRequesterImpl::getMeasurements(std::vector<uint8_t>& measurements)
{
    if (doMeasurement(NULL) && !spdmResponder.dataMeas.empty())
    {
        measurements = spdmResponder.dataMeas;
        spdmResponder.dataMeas.clear();
        spdmResponder.dataCert.clear();
        return true;
    }
    return false;
}

bool SPDMRequesterImpl::getCertificate(std::vector<uint8_t>& certificate)
{
    if (doAuthentication() && !spdmResponder.dataCert.empty())
    {
        certificate = spdmResponder.dataCert;
        return true;
    }
    return false;
}

bool SPDMRequesterImpl::getVCA(bool onlyVersion)
{
    return_status status;
    status = libspdm_init_connection(spdmResponder.pspdmContext, onlyVersion);
    if (RETURN_ERROR(status))
    {
        std::stringstream ss;
        ss << "0x" << std::uppercase << std::setfill('0') << std::setw(4)
           << std::hex << status;
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SPDMRequesterImpl libspdm_init_connection Error!- " + ss.str())
                .c_str());
        free_pool(spdmResponder.pspdmContext);
        spdmResponder.pspdmContext = nullptr;
        return false;
    }
    return true;
}

bool SPDMRequesterImpl::isConnStateNegotiated()
{
    uint32_t dataSize;
    uint32_t connState;
    return_status status;
    libspdm_data_parameter_t parameter;
    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

    dataSize = sizeof(connState);
    status = libspdm_get_data(spdmResponder.pspdmContext,
                              LIBSPDM_DATA_CONNECTION_STATE, &parameter,
                              &connState, &dataSize);
    if (RETURN_ERROR(status))
    {
        return false;
    }
    if (connState != LIBSPDM_CONNECTION_STATE_NEGOTIATED)
    {
        return false;
    }
    return true;
}

SPDMRequesterImpl::SPDMRequesterImpl(
    std::shared_ptr<boost::asio::io_context> io,
    std::shared_ptr<sdbusplus::asio::connection> con,
    std::shared_ptr<spdm_transport::SPDMTransport> trans,
    spdm_transport::TransportEndPoint& endPointDevice,
    SPDMConfiguration& spdmConfig) :
    ioc(io),
    conn(con), spdmTrans(trans), transResponder(endPointDevice),
    spdmRequesterCfg(spdmConfig)
{
    setCertificatePath(spdmRequesterCfg.certPath);
    if (!setupResponder(transResponder))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl init set up failed!");
    }
    if (!settingFromConfig())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl settingsfromConfig failed!");
    }
}

} // namespace spdm_app_lib
