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

#include "spdmapplib_responder_impl.hpp"

#include "mctp_wrapper.hpp"

namespace spdm_app_lib
{
/*Callback functions for libspdm */

libspdm_return_t SPDMResponderImpl::responderDeviceSendMessage(
    void* spdmContext, size_t requestSize, const void* request,
    uint64_t timeout)
{
    void* spdmAppContext = nullptr;

    if (!getSPDMAppContext(spdmContext, spdmAppContext))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    SPDMResponderImpl* spdmTmp =
        reinterpret_cast<SPDMResponderImpl*>(spdmAppContext);
    std::vector<uint8_t> data = formSendMessage(requestSize, request);
    if (!spdmTmp->deviceSendMessage(spdmContext, data, timeout))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    return spdm_app_lib::error_codes::returnSuccess;
}

libspdm_return_t SPDMResponderImpl::responderDeviceReceiveMessage(
    void* spdmContext, size_t* responseSize, void** response, uint64_t timeout)
{
    void* spdmAppContext = nullptr;

    if (!getSPDMAppContext(spdmContext, spdmAppContext))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    SPDMResponderImpl* spdmTmp =
        reinterpret_cast<SPDMResponderImpl*>(spdmAppContext);
    std::vector<uint8_t> rspData{};
    if (!spdmTmp->deviceReceiveMessage(spdmContext, rspData, timeout))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    formRecvMessage(responseSize, response, rspData);
    return spdm_app_lib::error_codes::returnSuccess;
}

void spdmServerConnectionStateCallback(
    void* spdmContext, libspdm_connection_state_t connectionState)
{
    void* spdmAppContext = nullptr;
    if (!getSPDMAppContext(spdmContext, spdmAppContext))
    {
        return;
    }
    SPDMResponderImpl* spdmTmp =
        reinterpret_cast<SPDMResponderImpl*>(spdmAppContext);
    spdmTmp->processConnectionState(spdmContext, connectionState);
}

void spdmServerSessionStateCallback(void* spdmContext, uint32_t sessionID,
                                    libspdm_session_state_t sessionState)
{
    void* spdmAppContext = nullptr;

    if (!getSPDMAppContext(spdmContext, spdmAppContext))
    {
        return;
    }
    SPDMResponderImpl* spdmTmp =
        reinterpret_cast<SPDMResponderImpl*>(spdmAppContext);
    return spdmTmp->processSessionState(spdmContext, sessionID, sessionState);
}

SPDMResponderImpl::~SPDMResponderImpl()
{
    for (auto& item : spdmPool)
    {
        freeSpdmContext(item);
    }
}

bool SPDMResponderImpl::updateSPDMPool(
    spdm_transport::TransportEndPoint& transEndpoint)
{
    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.transEP == transEndpoint);
    });
    if (it == spdmPool.end())
    {
        return false;
    }
    if (it->spdmContext != nullptr)
    {
        freeSpdmContext(*it);
    }
    spdmPool.erase(spdmPool.begin() + (it - spdmPool.begin()));
    return true;
}

bool SPDMResponderImpl::addNewDevice(
    spdm_transport::TransportEndPoint& transEndpoint)
{
    spdmItem newItem;

    if (!spdmInit(newItem, transEndpoint, spdmTrans->getSPDMtransport(),
                  responderDeviceSendMessage, responderDeviceReceiveMessage))
    {
        return false;
    }

    libspdm_register_session_state_callback_func(
        newItem.spdmContext, spdmServerSessionStateCallback);

    libspdm_register_connection_state_callback_func(
        newItem.spdmContext, spdmServerConnectionStateCallback);
    spdmPool.push_back(newItem);
    return true;
}

bool SPDMResponderImpl::initSpdmContext()
{
    libspdm_data_parameter_t parameter;
    void* tmpThis = static_cast<void*>(this);

    initGetSetParameter(parameter, operationSet);
    return validateSpdmRc(libspdm_set_data(
        spdmPool.back().spdmContext, LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter,
        &tmpThis, sizeof(void*)));
}

bool SPDMResponderImpl::addData(
    spdm_transport::TransportEndPoint& transEndpoint,
    const std::vector<uint8_t>& data)
{
    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.transEP == transEndpoint);
    });
    if (it == spdmPool.end())
    {
        return false;
    }
    it->data = std::move(data);
    return true;
}

bool SPDMResponderImpl::processSPDMMessage(
    spdm_transport::TransportEndPoint& transEndpoint)
{
    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.transEP == transEndpoint);
    });
    if (it == spdmPool.end())
    {
        return false;
    }
    if (it->data.empty())
    {
        return false;
    }
    return validateSpdmRc(libspdm_responder_dispatch_message(it->spdmContext));
}

bool SPDMResponderImpl::msgRecvCallback(
    spdm_transport::TransportEndPoint& transEP,
    const std::vector<uint8_t>& data)
{
    auto it = find_if(spdmPool.begin(), spdmPool.end(),
                      [&](spdmItem item) { return (item.transEP == transEP); });
    if (it == spdmPool.end())
    {
        if (!addNewDevice(transEP))
        {
            return false;
        }
        if (!initSpdmContext())
        {
            return false;
        }
        if (!spdmSetConfigData(spdmPool.back(), spdmResponderCfg))
        {
            return false;
        }
    }
    if (!addData(transEP, data))
    {
        return false;
    }
    return processSPDMMessage(transEP);
}

bool SPDMResponderImpl::deviceReceiveMessage(void* spdmContext,
                                             std::vector<uint8_t>& response,
                                             uint64_t /*timeout*/)
{
    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.spdmContext == spdmContext);
    });
    if (it == spdmPool.end())
    {
        return false;
    }
    response = std::move(it->data);
    return true;
}

bool SPDMResponderImpl::deviceSendMessage(void* spdmContext,
                                          const std::vector<uint8_t>& request,
                                          uint64_t timeout)
{
    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.spdmContext == spdmContext);
    });
    if (it == spdmPool.end())
    {
        return false;
    }
    int rc = spdmTrans->asyncSendData(it->transEP, request, timeout);
    if (rc != spdm_app_lib::error_codes::returnSuccess)
    {
        return false;
    }
    return true;
}

void SPDMResponderImpl::processConnectionState(
    void* spdmContext, libspdm_connection_state_t connectionState)
{
    constexpr uint8_t rootCertSlotID = 1;
    size_t certChainSize = 0;
    size_t rootCertSize = 0;
    spdm_version_number_t spdmVersion;
    libspdm_data_parameter_t parameter;

    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.spdmContext == spdmContext);
    });
    if (it == spdmPool.end())
    {
        return;
    }
    it->connectStatus = connectionState;
    switch (connectionState)
    {
        case LIBSPDM_CONNECTION_STATE_NOT_STARTED:
            /* clear preserved state*/
            break;

        case LIBSPDM_CONNECTION_STATE_NEGOTIATED:
            freeAllocatedMemory(it->certChain);
            freeAllocatedMemory(it->rootCert);
            if (it->useVersion == 0)
            {
                initGetSetParameter(parameter, operationGet);
                if (!spdmGetData(*it, LIBSPDM_DATA_SPDM_VERSION, spdmVersion,
                                 parameter))
                {
                    break;
                }
                it->useVersion = static_cast<uint8_t>(
                    spdmVersion >> SPDM_VERSION_NUMBER_SHIFT_BIT);
            }
            if (!spdmGetAlgo(*it, it->useMeasurementHashAlgo, it->useAsymAlgo,
                             it->useHashAlgo, it->useReqAsymAlgo))
            {
                break;
            }
            if (!libspdm_read_responder_public_certificate_chain(
                    it->useHashAlgo, it->useAsymAlgo, &it->certChain,
                    &certChainSize, nullptr, nullptr))
            {
                break;
            }
            if (!libspdm_read_responder_public_certificate_chain_per_slot(
                    rootCertSlotID, it->useHashAlgo, it->useAsymAlgo,
                    &it->rootCert, &rootCertSize, NULL, NULL))
            {
                break;
            }
            initGetSetParameter(parameter, operationSet);
            for (uint8_t index = 0;
                 index < static_cast<uint8_t>(spdmResponderCfg.slotcount);
                 index++)
            {
                parameter.additional_data[0] = index;
                if (index == rootCertSlotID)
                {
                    if (!validateSpdmRc(libspdm_set_data(
                            it->spdmContext,
                            LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter,
                            it->rootCert, rootCertSize)))
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "SPDMResponderImpl::processConnectionState set Certificate 1 FAILED!!");
                        break;
                    }
                }
                else
                {
                    if (!validateSpdmRc(libspdm_set_data(
                            it->spdmContext,
                            LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter,
                            it->certChain, certChainSize)))
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "SPDMResponderImpl::processConnectionState set Certificate FAILED!!");
                        break;
                    }
                }
            }
            break;

        default:
            break;
    }
}

void SPDMResponderImpl::processSessionState(
    void* spdmContext, uint32_t sessionID, libspdm_session_state_t sessionState)
{
    uint8_t u8Value = 0;
    libspdm_data_parameter_t parameter;

    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.spdmContext == spdmContext);
    });
    if (it == spdmPool.end())
    {
        return;
    }

    switch (sessionState)
    {
        case LIBSPDM_SESSION_STATE_NOT_STARTED:
            /* TODO: End the Session*/
            break;
        case LIBSPDM_SESSION_STATE_HANDSHAKING:
            /* collect session policy*/
            it->sessionId = sessionID;
            if (it->useVersion >= SPDM_MESSAGE_VERSION_12)
            {
                initGetSetParameter(parameter, operationSession);
                *reinterpret_cast<uint32_t*>(parameter.additional_data) =
                    sessionID;
                if (!spdmGetData(*it, LIBSPDM_DATA_SESSION_POLICY, u8Value,
                                 parameter))
                {
                    break;
                }
            }
            break;
        case LIBSPDM_SESSION_STATE_ESTABLISHED:
            /* no action*/
            break;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "SPDMResponderImpl::processConnectionState should not goto here!!");
            break;
    }
}

SPDMResponderImpl::SPDMResponderImpl(
    std::shared_ptr<boost::asio::io_context> io,
    std::shared_ptr<sdbusplus::asio::connection> con,
    std::shared_ptr<spdm_transport::SPDMTransport> trans,
    SPDMConfiguration& spdmConfig) :
    ioc(io),
    conn(con), spdmTrans(trans), spdmResponderCfg(spdmConfig)
{
    using namespace std::placeholders;
    setCertificatePath(spdmResponderCfg.certPath);
    spdmTrans->setListener(
        std::bind(&SPDMResponderImpl::msgRecvCallback, this, _1, _2));
}

} // namespace spdm_app_lib
