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
    if ((capability & exeConnectionDigest))
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

    if (!(capability & exeConnectionCert))
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

    if (!setCertificateChain())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::doMeasurement cannot set up certificate chain for mutual authentication.");
        return false;
    }

    if ((capability & exeConnectionChal))
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

    if (!(capability & exeConnectionMeas))
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
        phosphor::logging::log<phosphor::logging::level::ERR>(
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

bool SPDMRequesterImpl::getMeasurements(std::vector<uint8_t>& measurements,
                                        uint8_t useSlotId)
{
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

bool SPDMRequesterImpl::getSignedMeasurements(
    const RedfishGetSignedMeasurementsRequest& request,
    RedfishGetSignedMeasurementsResponse& response)
{
    const std::string& nounce = request.nonce;
    if (nounce.size() != 32)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getSignedMeasurements invalid nounce length.");
        return false;
    }

    if (request.slotId < 0 || request.slotId > 7)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getSignedMeasurements invalid slot id.");
        return false;
    }

    const std::set<uint8_t>& measurementIndices = request.measurementIndices;
    if (measurementIndices.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getSignedMeasurements invalid empty indice.");
        return false;
    }

    if (measurementIndices.find(0) != measurementIndices.end() &&
        measurementIndices.size() > 1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getSignedMeasurements invalid operation by given 0 and other indice.");
        return false;
    }

    if (measurementIndices.find(0xff) != measurementIndices.end() &&
        measurementIndices.size() > 1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::getSignedMeasurements invalid operation by given 0xff and other indice.");
        return false;
    }

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

bool SPDMRequesterImpl::startSecureSession(bool usePsk, uint32_t& sessionId,
                                           uint8_t& heartbeatPeriod,
                                           uint8_t useSlotId)
{
    uint8_t useMeasurementSummaryHashType =
        SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH;
    uint8_t measurementHash[LIBSPDM_MAX_HASH_SIZE];
    uint8_t sessionPolicy =
        SPDM_KEY_EXCHANGE_REQUEST_SESSION_POLICY_TERMINATION_POLICY_RUNTIME_UPDATE;

    if (!setupSpdmRequester())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::startSecureSession setupSpdmRequester failed!");
        return false;
    }

    if (!doAuthentication(useSlotId))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::startSecureSession doAuthentication failed!");
        return false;
    }

    if (!setCertificateChain())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::startSecureSession cannot set up certificate chain for mutual authentication.");
        return false;
    }

    return validateSpdmRc(libspdm_start_session(
        spdmResponder.spdmContext, usePsk, useMeasurementSummaryHashType,
        useSlotId, sessionPolicy, &sessionId, &heartbeatPeriod,
        measurementHash));
}

bool SPDMRequesterImpl::endSecureSession(uint32_t sessionId)
{
    uint8_t endSessionAttributes =
        0x00000001; // preservce responder negotiated state

    bool result = validateSpdmRc(libspdm_stop_session(
        spdmResponder.spdmContext, sessionId, endSessionAttributes));
    freeSpdmContext(spdmResponder);
    return result;
}

bool SPDMRequesterImpl::sendHeartbeat(uint32_t sessionId)
{
    return validateSpdmRc(
        libspdm_heartbeat(spdmResponder.spdmContext, sessionId));
}

bool SPDMRequesterImpl::updateKey(uint32_t sessionId, bool singleDirection)
{
    return validateSpdmRc(libspdm_key_update(spdmResponder.spdmContext,
                                             sessionId, singleDirection));
}

bool SPDMRequesterImpl::sendSecuredMessage(uint32_t sessionId,
                                           const std::vector<uint8_t>& request,
                                           std::vector<uint8_t>& response,
                                           bool isAppMessage)
{
    size_t requestSize = request.size();
    size_t responseSize = LIBSPDM_MAX_MESSAGE_BUFFER_SIZE;
    uint8_t responseArray[LIBSPDM_MAX_MESSAGE_BUFFER_SIZE];
    const uint8_t* requestArray = request.data();
    if (!validateSpdmRc(libspdm_send_receive_data(
            spdmResponder.spdmContext, &sessionId, isAppMessage, requestArray,
            requestSize, responseArray, &responseSize)))
    {
        return false;
    }
    std::vector<uint8_t> buffer(responseArray, responseArray + responseSize);
    response = buffer;
    return true;
}

bool SPDMRequesterImpl::setCertificateChain()
{
    uint32_t baseHashAlgo;
    uint32_t baseAsymAlgo;
    uint32_t measurementHashAlgo;
    uint16_t reqAsymAlgo;
    size_t certChainSize = 0;
    void* certChain;
    libspdm_data_parameter_t parameter;

    if (!(spdmRequesterCfg.capability &
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "SPDMRequesterImpl::setCerticateChain Ignore to set certificate due to unsupported mutual authentication.");
        return true;
    }

    if (!spdmGetAlgo(spdmResponder, measurementHashAlgo, baseAsymAlgo,
                     baseHashAlgo, reqAsymAlgo))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::setCerticateChain failed to get negotiated algorithms for mutual authentication.");
        return false;
    }

    if (!libspdm_read_requester_public_certificate_chain(
            baseHashAlgo, reqAsymAlgo, &certChain, &certChainSize, nullptr,
            nullptr))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::setCerticateChain failed to read public certificate chain for mutual authentication.");
        return false;
    }

    initGetSetParameter(parameter, operationSet);
    if (!validateSpdmRc(libspdm_set_data(spdmResponder.spdmContext,
                                         LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                         &parameter, certChain, certChainSize)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMRequesterImpl::setCerticateChain failed to set certificate chain for mutual authentication.");
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
    mUseMeasurementOperation =
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
}

} // namespace spdm_app_lib
