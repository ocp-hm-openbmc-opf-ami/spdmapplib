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

#include "mctp_wrapper.hpp"

namespace spdm_app_lib
{
/*Callback functions for libspdm */

libspdm_return_t requesterDeviceSendMessage(void* spdmContext,
                                            size_t requestSize,
                                            const void* request,
                                            uint64_t timeout)
{
    void* spdmAppContext = nullptr;

    if (!getSPDMAppContext(spdmContext, spdmAppContext))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    SPDMRequesterImpl* spdmTmp =
        reinterpret_cast<SPDMRequesterImpl*>(spdmAppContext);
    std::vector<uint8_t> data = formSendMessage(requestSize, request);
    if (!spdmTmp->deviceSendMessage(spdmContext, data, timeout))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    return spdm_app_lib::error_codes::returnSuccess;
}

libspdm_return_t requesterDeviceReceiveMessage(void* spdmContext,
                                               size_t* responseSize,
                                               void** response,
                                               uint64_t timeout)
{
    void* spdmAppContext = nullptr;

    if (!getSPDMAppContext(spdmContext, spdmAppContext))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    SPDMRequesterImpl* spdmTmp =
        reinterpret_cast<SPDMRequesterImpl*>(spdmAppContext);
    std::vector<uint8_t> rspData{};
    if (!spdmTmp->deviceReceiveMessage(spdmContext, rspData, timeout))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    formRecvMessage(responseSize, response, rspData);
    return spdm_app_lib::error_codes::returnSuccess;
}

SPDMRequesterImpl::~SPDMRequesterImpl()
{
    freeSpdmContext(spdmResponder);
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
}

bool SPDMRequesterImpl::deviceReceiveMessage(void* /*spdmContext*/,
                                             std::vector<uint8_t>& response,
                                             uint64_t /*timeout*/)
{
    if (spdmResponder.data.empty())
    {
        return false;
    }
    response = std::move(spdmResponder.data);
    return true;
}

bool SPDMRequesterImpl::deviceSendMessage(void* /*spdmContext*/,
                                          const std::vector<uint8_t>& request,
                                          uint64_t timeout)
{
    std::vector<uint8_t> response{};
    int rc = spdmTrans->sendRecvData(spdmResponder.transEP, request, timeout,
                                     response);
    if (rc != spdm_app_lib::error_codes::returnSuccess)
    {
        return false;
    }
    addData(spdmResponder.transEP, response);
    return true;
}

bool SPDMRequesterImpl::initSpdmContext()
{
    libspdm_data_parameter_t parameter;
    void* tmpThis = static_cast<void*>(this);

    initGetSetParameter(parameter, operationSet);
    return validateSpdmRc(libspdm_set_data(
        spdmResponder.spdmContext, LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter,
        &tmpThis, sizeof(void*)));
}

bool SPDMRequesterImpl::doAuthentication(void)
{
    uint8_t slotMask = 0;
    uint8_t useSlotId = 0;
    std::array<uint8_t, LIBSPDM_MAX_CERT_CHAIN_SIZE> certChain{0};
    std::array<uint8_t, LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT>
        totalDigestBuffer{0};

    spdmResponder.dataCert.clear();
    size_t certChainSize = certChain.size();

    if (!getVCA(false))
    {
        return false;
    }

    if (!isConnStateNegotiated())
    {
        return false;
    }
    /** Executing following functions.
        get_digest
        get_certificate
    **/
    if ((exeConnection & exeConnectionDigest))
    {
        if (!validateSpdmRc(libspdm_get_digest(spdmResponder.spdmContext,
                                               &slotMask, &totalDigestBuffer)))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "SPDMRequesterImpl::doAuthentication libspdm_get_digest Failed");
            freeSpdmContext(spdmResponder);
            return false;
        }
    }

    if (!(exeConnection & exeConnectionCert))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::doAuthentication Certificate CAPS Not Supported!");
        return false;
    }

    if (!validateSpdmRc(libspdm_get_certificate(
            spdmResponder.spdmContext, useSlotId, &certChainSize, &certChain)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::doAuthentication libspdm_get_certificate Failed");
        freeSpdmContext(spdmResponder);
        return false;
    }
    // Keep certificate to reserved vector.
    spdmResponder.dataCert.insert(spdmResponder.dataCert.end(),
                                  certChain.begin(),
                                  certChain.begin() + certChainSize);
    return true;
}

bool SPDMRequesterImpl::doMeasurement(const uint32_t* session_id)
{
    uint8_t useSlotId = 0;
    uint8_t numberOfBlocks = 0;
    uint32_t measurementRecordLength = 0;
    constexpr size_t measurementTranscriptSize = 0x4096;
    std::array<uint8_t, LIBSPDM_MAX_HASH_SIZE> measurementHash{0};
    std::array<uint8_t, LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE> measurement{0};
    std::array<uint8_t, measurementTranscriptSize> measurementTranscript{0};
    spdmResponder.dataMeas.clear();

    if (spdmResponder.spdmContext == nullptr)
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

    if ((exeConnection & exeConnectionChal))
    {
        if (!validateSpdmRc(
                libspdm_challenge(spdmResponder.spdmContext, useSlotId,
                                  SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH,
                                  &measurementHash, nullptr)))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "SPDMRequesterImpl::doMeasurement libspdm_challenge Failed!");
            freeSpdmContext(spdmResponder);
            return false;
        }
    }

    if (!(exeConnection & exeConnectionMeas))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::doMeasurement Meas CAP not Supported!");
        return false;
    }

    libspdm_init_msg_log(spdmResponder.spdmContext, &measurementTranscript,
                         measurementTranscript.size());
    libspdm_set_msg_log_mode(spdmResponder.spdmContext,
                             LIBSPDM_MSG_LOG_MODE_ENABLE);
    measurementRecordLength = measurement.size();
    if (!validateSpdmRc(libspdm_get_measurement(
            spdmResponder.spdmContext, session_id,
            SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
            mUseMeasurementOperation, useSlotId & 0xF, nullptr, &numberOfBlocks,
            &measurementRecordLength, &measurement)))
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "SPDMRequesterImpl::doMeasurement libspdm_get_measurements Failed!");
        spdmResponder.dataMeas.clear();
        return false;
    }

    // Keep measurement to reserved vector.
    size_t transcriptSize = libspdm_get_msg_log_size(spdmResponder.spdmContext);
    spdmResponder.dataMeas.insert(
        spdmResponder.dataMeas.end(), measurementTranscript.begin(),
        measurementTranscript.begin() + transcriptSize);
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
    if (!validateSpdmRc(
            libspdm_init_connection(spdmResponder.spdmContext, onlyVersion)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getVCA Failed!");
        freeSpdmContext(spdmResponder);
        return false;
    }
    return true;
}

bool SPDMRequesterImpl::isConnStateNegotiated()
{
    uint32_t connState = 0;
    libspdm_data_parameter_t parameter;

    initGetSetParameter(parameter, operationGet);
    if (!spdmGetData(spdmResponder, LIBSPDM_DATA_CONNECTION_STATE, connState,
                     parameter))
    {
        return false;
    }
    if (connState != LIBSPDM_CONNECTION_STATE_NEGOTIATED)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::isConnStateNegotiated state Not Negotiated!");
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
    conn(con), spdmTrans(trans), spdmRequesterCfg(spdmConfig)
{
    setCertificatePath(spdmRequesterCfg.certPath);
    if (!spdmInit(spdmResponder, endPointDevice, spdmTrans->getSPDMtransport(),
                  requesterDeviceSendMessage, requesterDeviceReceiveMessage))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl SPDM init failed!");
    }
    mUseMeasurementOperation =
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
    if (!initSpdmContext())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl init SPDM Context failed!");
    }
    if (!spdmSetConfigData(spdmResponder, spdmRequesterCfg))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDMRequesterImpl spdmSetConfigData failed!");
    }
}

} // namespace spdm_app_lib
