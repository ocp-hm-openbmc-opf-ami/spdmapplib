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
#include "spdmapplib_responder_impl.hpp"
extern "C"
{
#include "library/spdm_transport_none_lib.h"
}
#include "mctp_wrapper.hpp"

namespace spdm_app_lib
{
/*Callback functions for libspdm */

libspdm_return_t responderDeviceSendMessage(void* spdmContext,
                                            size_t requestSize,
                                            const void* request,
                                            uint64_t timeout)
{
    void* spdmAppContext = nullptr;

    if (!getSPDMAppContext(spdmContext, spdmAppContext))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    SPDMResponderImpl* spdmTmp =
        reinterpret_cast<SPDMResponderImpl*>(spdmAppContext);
    uint8_t* requestPayload =
        reinterpret_cast<uint8_t*>(const_cast<void*>(request));
    std::vector<uint8_t> data{};
    data.push_back(static_cast<uint8_t>(mctpw::MessageType::spdm));
    for (uint32_t j = 0; j < requestSize; j++)
    {
        data.push_back(*(requestPayload + j));
    }
    if (!spdmTmp->deviceSendMessage(spdmContext, data, timeout))
    {
        return spdm_app_lib::error_codes::generalReturnError;
    }
    return spdm_app_lib::error_codes::returnSuccess;
}

libspdm_return_t responderDeviceReceiveMessage(void* spdmContext,
                                               size_t* responseSize,
                                               void** response,
                                               uint64_t timeout)
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
    *responseSize = rspData.size() - 1; // skip MessageType byte
    std::copy(rspData.begin() + 1, rspData.end(),
              reinterpret_cast<uint8_t*>(*response));
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
        if (item.spdmContext)
        {
            freeSpdmContext(item);
        }
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

    if (!spdmInit(newItem, transEndpoint, responderDeviceSendMessage,
                  responderDeviceReceiveMessage,
                  spdm_transport_none_encode_message,
                  spdm_transport_none_decode_message,
                  spdm_transport_none_get_header_size))
    {
        return false;
    }

    if (!validateSpdmRc(libspdm_register_session_state_callback_func(
            newItem.spdmContext, spdmServerSessionStateCallback)))
    {
        return false;
    }

    if (!validateSpdmRc(libspdm_register_connection_state_callback_func(
            newItem.spdmContext, spdmServerConnectionStateCallback)))
    {
        return false;
    }
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
    bool res;
    void* data;
    size_t dataSize = 0;
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
            /* clear perserved state*/
            break;
        case LIBSPDM_CONNECTION_STATE_AFTER_VERSION:
            // TODO
            // Pre created for some actions needed in this state in the future.
            break;
        case LIBSPDM_CONNECTION_STATE_AFTER_CAPABILITIES:
            // TODO
            // Pre created for some actions needed in this state in the future.
            break;
        case LIBSPDM_CONNECTION_STATE_NEGOTIATED:
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
            res = libspdm_read_responder_public_certificate_chain(
                it->useHashAlgo, it->useAsymAlgo, &data, &dataSize, nullptr,
                nullptr);
            if (res)
            {
                initGetSetParameter(parameter, operationSet);
                if (!spdmSetData(
                        *it, LIBSPDM_DATA_LOCAL_SLOT_COUNT,
                        static_cast<uint8_t>(spdmResponderCfg.slotcount),
                        parameter))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "SPDMResponderImpl::processConnectionState Slot Count FAILED!!");
                    break;
                }
                for (uint8_t index = 0;
                     index < static_cast<uint8_t>(spdmResponderCfg.slotcount);
                     index++)
                {
                    parameter.additional_data[0] = index;
                    if (!validateSpdmRc(libspdm_set_data(
                            it->spdmContext,
                            LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN, &parameter,
                            data, dataSize)))
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "SPDMResponderImpl::processConnectionState set Certificate FAILED!!");
                        break;
                    }
                }
                /* do not free it*/
            }
            break;
        case LIBSPDM_CONNECTION_STATE_AFTER_DIGESTS:
            // TODO
            // Pre created for some actions needed in this state in the future.
            break;
        case LIBSPDM_CONNECTION_STATE_AFTER_CERTIFICATE:
            // TODO
            // Pre created for some actions needed in this state in the future.
            break;
        case LIBSPDM_CONNECTION_STATE_AUTHENTICATED:
            // TODO
            // Pre created for some actions needed in this state in the future.
            break;
        default:
            break;
    }
    return;
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
            // TODO
            // Pre created for some actions needed in this state in the future.
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
            // TODO
            // Pre created for some actions needed in this state in the future.
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