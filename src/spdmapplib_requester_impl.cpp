/*
// Copyright (c) 2022 Intel Corporation
//
// This software and the related documents are Intel copyrighted
// materials, and your use of them is governed by the express license
// under which they were provided to you ("License"). Unless the
// License provides otherwise, you may not use, modify, copy, publish,
// distribute, disclose or transmit this software or the related
// documents without Intel's prior written permission.
//
// This software and the related documents are provided as is, with no
// express or implied warranties, other than those that are expressly
// stated in the License.
*/

#include "spdmapplib_requester_impl.hpp"

#include "mctp_wrapper.hpp"

constexpr uint16_t certificateBufferLength = 1000;

namespace spdm_app_lib
{
/*Callback functions for libspdm */

libspdm_return_t SPDMRequesterImpl::requesterDeviceSendMessage(
    void* spdmContext, size_t requestSize, const void* request,
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

libspdm_return_t SPDMRequesterImpl::requesterDeviceReceiveMessage(
    void* spdmContext, size_t* responseSize, void** response, uint64_t timeout)
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

    if (!getCapabilities())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getCapabilities Failed!");
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

bool SPDMRequesterImpl::getCapabilities()
{
    libspdm_data_parameter_t parameter;
    initGetSetParameter(parameter, operationGet);
    if (!spdmGetData(spdmResponder, LIBSPDM_DATA_CAPABILITY_FLAGS, capability,
                     parameter))
    {
        return false;
    }
    return true;
}

bool SPDMRequesterImpl::doAuthentication(uint8_t useSlotId)
{
    uint8_t slotMask = 0;
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
    if (capability & capabilityDigestCert)
    {
        if (!validateSpdmRc(libspdm_get_digest(spdmResponder.spdmContext, NULL,
                                               &slotMask, &totalDigestBuffer)))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "SPDMRequesterImpl::doAuthentication libspdm_get_digest Failed");
            freeSpdmContext(spdmResponder);
            return false;
        }
    }

    if (!(capability & capabilityDigestCert))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::doAuthentication Certificate CAPS Not Supported!");
        return false;
    }

    if (!validateSpdmRc(libspdm_get_certificate(spdmResponder.spdmContext, NULL,
                                                useSlotId, &certChainSize,
                                                &certChain)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::doAuthentication libspdm_get_certificate_choose_length Failed");
        freeSpdmContext(spdmResponder);
        return false;
    }
    // Keep certificate to reserved vector.
    spdmResponder.dataCert.insert(spdmResponder.dataCert.end(),
                                  certChain.begin(),
                                  certChain.begin() + certChainSize);
    return true;
}

bool SPDMRequesterImpl::doMeasurement(const uint32_t* session_id,
                                      uint8_t useSlotId)
{
    uint8_t numberOfBlocks = 0;
    uint32_t measurementRecordLength = 0;
    constexpr size_t measurementTranscriptSize = 0x4096;
    std::array<uint8_t, LIBSPDM_MAX_HASH_SIZE> measurementHash{0};
    std::array<uint8_t, LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE> measurement{0};
    std::array<uint8_t, measurementTranscriptSize> measurementTranscript{0};
    spdmResponder.dataMeas.clear();

    if (capability & capabilityChallenge)
    {
        if (!validateSpdmRc(
                libspdm_challenge(spdmResponder.spdmContext, NULL, useSlotId,
                                  SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH,
                                  &measurementHash, nullptr)))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "SPDMRequesterImpl::doMeasurement libspdm_challenge Failed!");
            freeSpdmContext(spdmResponder);
            return false;
        }
    }

    if ((capability & capabilityMeas) || (capability & capabilityMeasSign))
    {
        libspdm_init_msg_log(spdmResponder.spdmContext, &measurementTranscript,
                             measurementTranscript.size());
        libspdm_set_msg_log_mode(spdmResponder.spdmContext,
                                 LIBSPDM_MSG_LOG_MODE_ENABLE);
        measurementRecordLength = measurement.size();
        if (!validateSpdmRc(libspdm_get_measurement(
                spdmResponder.spdmContext, session_id,
                SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
                mUseMeasurementOperation, useSlotId & 0xF, nullptr,
                &numberOfBlocks, &measurementRecordLength, &measurement)))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "SPDMRequesterImpl::doMeasurement libspdm_get_measurements Failed!");
            spdmResponder.dataMeas.clear();
            return false;
        }

        // Keep measurement to reserved vector.
        size_t transcriptSize =
            libspdm_get_msg_log_size(spdmResponder.spdmContext);
        spdmResponder.dataMeas.insert(
            spdmResponder.dataMeas.end(), measurementTranscript.begin(),
            measurementTranscript.begin() + transcriptSize);
        return true;
    }
    phosphor::logging::log<phosphor::logging::level::ERR>(
        "SPDMRequesterImpl::doMeasurement Meas CAP not Supported!");
    return false;
}

bool SPDMRequesterImpl::getMeasurements(std::vector<uint8_t>& measurements,
                                        uint8_t measurementIndex,
                                        uint8_t useSlotId)
{
    mUseMeasurementOperation = measurementIndex;

    if (!setupSpdmRequester())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getMeasurements setupSpdmRequester failed!");
        return false;
    }
    if (!doAuthentication(useSlotId))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDMRequesterImpl::getMeasurements doAuthentication failed!");
        return false;
    }

    if (spdmResponder.dataCert.empty())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDMRequesterImpl::getMeasurements Certificate is Empty failed!");
        return false;
    }

    if (!doMeasurement(NULL, useSlotId))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDMRequesterImpl::getMeasurements doMeasurement failed!");
        return false;
    }

    if (spdmResponder.dataMeas.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getMeasurements Measurements is Empty!");
        return false;
    }

    measurements = spdmResponder.dataMeas;
    freeSpdmContext(spdmResponder);
    return true;
}

bool SPDMRequesterImpl::getCertificate(std::vector<uint8_t>& certificate,
                                       uint8_t useSlotId)
{
    if (!setupSpdmRequester())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getCertificate setupSpdmRequester failed!");
        return false;
    }

    if (!doAuthentication(useSlotId))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getCertificate doAuthentication failed!");
        return false;
    }

    if (spdmResponder.dataCert.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getCertificate certificate is Empty!");
        return false;
    }

    certificate = spdmResponder.dataCert;
    freeSpdmContext(spdmResponder);
    return true;
}

bool SPDMRequesterImpl::setupSpdmRequester()
{
    if (!spdmInit(spdmResponder, responderEndpoint,
                  spdmTrans->getSPDMtransport(), requesterDeviceSendMessage,
                  requesterDeviceReceiveMessage))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::setupSpdmRequester SPDM init failed!");
        return false;
    }

    if (!initSpdmContext())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::setupSpdmRequester init SPDM Context failed!");
        return false;
    }

    if (!spdmSetConfigData(spdmResponder, spdmRequesterCfg))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDMRequesterImpl::setupSpdmRequester spdmSetConfigData failed!");
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
    conn(con), spdmTrans(trans), responderEndpoint(endPointDevice),
    spdmRequesterCfg(spdmConfig)
{
    setCertificatePath(spdmRequesterCfg.certPath);
}

} // namespace spdm_app_lib
