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

return_status responderDeviceSendMessage(void* spdmContext, uintn requestSize,
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
    uint8_t* requestPayload = (uint8_t*)request;
    SPDMResponderImpl* pspdmTmp =
        reinterpret_cast<SPDMResponderImpl*>(spdmAppContext);
    std::vector<uint8_t> data{};
    data.push_back(static_cast<uint8_t>(mctpw::MessageType::spdm));
    for (uint32_t j = 0; j < requestSize; j++)
    {
        data.push_back(*(requestPayload + j));
    }
    return pspdmTmp->deviceSendMessage(spdmContext, data, timeout);
}

return_status responderDeviceReceiveMessage(void* spdmContext,
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
    std::vector<uint8_t> rspData{};
    SPDMResponderImpl* pspdmTmp =
        reinterpret_cast<SPDMResponderImpl*>(spdmAppContext);
    status = pspdmTmp->deviceReceiveMessage(spdmContext, rspData, timeout);
    *responseSize = rspData.size() - 1; // skip MessageType byte
    std::copy(rspData.begin() + 1, rspData.end(),
              reinterpret_cast<uint8_t*>(response));
    return status;
}

void spdmServerConnectionStateCallback(
    void* spdmContext, libspdm_connection_state_t connectionState)
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
        return;
    }
    SPDMResponderImpl* pspdmTmp =
        reinterpret_cast<SPDMResponderImpl*>(spdmAppContext);
    pspdmTmp->processConnectionState(spdmContext, connectionState);
}

void spdmServerSessionStateCallback(void* spdmContext, uint32_t sessionID,
                                    libspdm_session_state_t sessionState)
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
        return;
    }
    SPDMResponderImpl* pspdmTmp =
        reinterpret_cast<SPDMResponderImpl*>(spdmAppContext);
    return pspdmTmp->processSessionState(spdmContext, sessionID, sessionState);
}

SPDMResponderImpl::~SPDMResponderImpl()
{
    for (auto& item : spdmPool)
    {
        if (item.pspdmContext)
        {
            free_pool(item.pspdmContext);
            item.pspdmContext = nullptr;
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
    if (it->pspdmContext != nullptr)
    {
        free_pool(it->pspdmContext);
        it->pspdmContext = nullptr;
    }
    spdmPool.erase(spdmPool.begin() + (it - spdmPool.begin()));
    return true;
}

bool SPDMResponderImpl::addNewDevice(
    spdm_transport::TransportEndPoint& transEndpoint)
{
    spdmItem newItem;
    return_status status;

    newItem.pspdmContext = allocate_zero_pool(libspdm_get_context_size());
    if (newItem.pspdmContext == nullptr)
    {
        return false;
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "SPDMResponderImpl::addNewDevice");
    newItem.transEP = transEndpoint;
    newItem.useSlotId = 0;
    newItem.sessionId = 0;
    newItem.useVersion = 0;
    newItem.useReqAsymAlgo = 0;
    newItem.useMeasurementHashAlgo = 0;
    newItem.useAsymAlgo = 0;
    newItem.useHashAlgo = 0;
    newItem.connectStatus = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    newItem.data.clear();
    spdmPool.push_back(newItem);

    status = libspdm_init_context(spdmPool.back().pspdmContext);
    if (RETURN_ERROR(status))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SPDMResponderImpl::addNewDevice libspdm_init_context failed" +
             std::to_string(status))
                .c_str());
        return false;
    }
    libspdm_register_device_io_func(spdmPool.back().pspdmContext,
                                    responderDeviceSendMessage,
                                    responderDeviceReceiveMessage);
    libspdm_register_transport_layer_func(spdmPool.back().pspdmContext,
                                          spdm_transport_none_encode_message,
                                          spdm_transport_none_decode_message);

    status = libspdm_register_session_state_callback_func(
        spdmPool.back().pspdmContext, spdmServerSessionStateCallback);
    if (RETURN_ERROR(status))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SPDMResponderImpl::addNewDevice libspdm_register_session_state_callback_func failed" +
             std::to_string(status))
                .c_str());
        return false;
    }
    status = libspdm_register_connection_state_callback_func(
        spdmPool.back().pspdmContext, spdmServerConnectionStateCallback);
    if (RETURN_ERROR(status))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SPDMResponderImpl::addNewDevice libspdm_register_connection_state_callback_func failed" +
             std::to_string(status))
                .c_str());
        return false;
    }

    return settingFromConfig();
}

bool SPDMResponderImpl::settingFromConfig()
{
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;
    uint16_t u16Value;
    uint32_t u32Value;
    void* tmpThis = static_cast<void*>(this);
    return_status status;

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("SPDMResponderImpl::settingFromConfig Responder useSlotCount: " +
         std::to_string(spdmResponderCfg.slotcount))
            .c_str());

    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter,
                              &tmpThis, sizeof(void*));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u8Value = 0;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u32Value = spdmResponderCfg.capability;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u8Value = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u32Value = spdmResponderCfg.measHash;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u32Value = spdmResponderCfg.asym;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u16Value = (uint16_t)spdmResponderCfg.reqasym;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u32Value = spdmResponderCfg.hash;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u16Value = (uint16_t)spdmResponderCfg.dhe;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u16Value = (uint16_t)spdmResponderCfg.aead;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u16Value = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &u16Value,
                              sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    u8Value = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    status = libspdm_set_data(spdmPool.back().pspdmContext,
                              LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return false;
    }

    return true;
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
    return_status status;
    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.transEP == transEndpoint);
    });
    if (it == spdmPool.end())
    {
        return false;
    }
    if (it->data.size() > 0)
    {
        status = libspdm_responder_dispatch_message(it->pspdmContext);
        if (RETURN_ERROR(status))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                ("spdmRequesterImpl::setupResponder libspdm_responder_dispatch_message failed! status: " +
                 std::to_string(status))
                    .c_str());
            return false;
        }
    }
    return true;
}

bool SPDMResponderImpl::msgRecvCallback(
    spdm_transport::TransportEndPoint& transEP,
    const std::vector<uint8_t>& data)
{
    auto it = find_if(spdmPool.begin(), spdmPool.end(),
                      [&](spdmItem item) { return (item.transEP == transEP); });
    if (it == spdmPool.end())
    {
        addNewDevice(transEP);
    }
    if (!addData(transEP, data))
    {
        return false;
    }
    return processSPDMMessage(transEP);
};

return_status SPDMResponderImpl::deviceReceiveMessage(
    void* spdmContext, std::vector<uint8_t>& response, uint64_t /*timeout*/)
{
    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.pspdmContext == spdmContext);
    });
    if (it == spdmPool.end())
    {
        return RETURN_DEVICE_ERROR;
    }
    response = std::move(it->data);
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("SPDMResponderImpl::deviceReceiveMessage responseSize: " +
         std::to_string(response.size()))
            .c_str());
    return RETURN_SUCCESS;
}

return_status SPDMResponderImpl::deviceSendMessage(
    void* spdmContext, const std::vector<uint8_t>& request, uint64_t timeout)
{
    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.pspdmContext == spdmContext);
    });
    if (it == spdmPool.end())
    {
        return RETURN_DEVICE_ERROR;
    }
    return spdmTrans->asyncSendData(it->transEP, request, timeout);
}

void SPDMResponderImpl::processConnectionState(
    void* spdmContext, libspdm_connection_state_t connectionState)
{
    void* data;
    uint32_t dataSize;
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;
    uint16_t u16Value;
    uint32_t u32Value;
    bool res;
    uint8_t index;
    spdm_version_number_t spdmVersion;
    return_status status;

    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.pspdmContext == spdmContext);
    });
    if (it == spdmPool.end())
        return;
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
                zero_mem(&parameter, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
                dataSize = sizeof(spdmVersion);
                status = libspdm_get_data(it->pspdmContext,
                                          LIBSPDM_DATA_SPDM_VERSION, &parameter,
                                          &spdmVersion, &dataSize);
                if (RETURN_ERROR(status))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Get Version failed:" +
                         std::to_string(status))
                            .c_str());
                    break;
                }
                it->useVersion =
                    (uint8_t)(spdmVersion >> SPDM_VERSION_NUMBER_SHIFT_BIT);
            }
            /* Provision new content*/
            zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

            dataSize = sizeof(u32Value);
            status = libspdm_get_data(it->pspdmContext,
                                      LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
                                      &parameter, &u32Value, &dataSize);
            if (RETURN_ERROR(status))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Get MeasurementHashAlgo failed:" +
                     std::to_string(status))
                        .c_str());
                break;
            }
            it->useMeasurementHashAlgo = u32Value;
            dataSize = sizeof(u32Value);
            status =
                libspdm_get_data(it->pspdmContext, LIBSPDM_DATA_BASE_ASYM_ALGO,
                                 &parameter, &u32Value, &dataSize);
            if (RETURN_ERROR(status))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Get AsymAlgo failed:" +
                     std::to_string(status))
                        .c_str());
                break;
            }
            it->useAsymAlgo = u32Value;
            dataSize = sizeof(u32Value);
            status =
                libspdm_get_data(it->pspdmContext, LIBSPDM_DATA_BASE_HASH_ALGO,
                                 &parameter, &u32Value, &dataSize);
            if (RETURN_ERROR(status))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Get HashAlgo failed:" +
                     std::to_string(status))
                        .c_str());
                break;
            }
            it->useHashAlgo = u32Value;

            dataSize = sizeof(u16Value);
            status = libspdm_get_data(it->pspdmContext,
                                      LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                                      &parameter, &u16Value, &dataSize);
            if (RETURN_ERROR(status))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Get ReqAsymAlgo failed:" +
                     std::to_string(status))
                        .c_str());
                break;
            }
            it->useReqAsymAlgo = u16Value;
            res = read_responder_public_certificate_chain(
                it->useHashAlgo, it->useAsymAlgo, &data, &dataSize, nullptr,
                nullptr);
            if (res)
            {
                zero_mem(&parameter, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                u8Value = static_cast<uint8_t>(spdmResponderCfg.slotcount);
                status = libspdm_set_data(
                    it->pspdmContext, LIBSPDM_DATA_LOCAL_SLOT_COUNT, &parameter,
                    &u8Value, sizeof(u8Value));
                if (RETURN_ERROR(status))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Set slotcount failed:" +
                         std::to_string(status))
                            .c_str());
                    break;
                }

                for (index = 0;
                     index < static_cast<uint8_t>(spdmResponderCfg.slotcount);
                     index++)
                {
                    parameter.additional_data[0] = index;
                    status = libspdm_set_data(
                        it->pspdmContext, LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                        &parameter, data, dataSize);
                    if (RETURN_ERROR(status))
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Set CertChain failed:" +
                             std::to_string(status) +
                             " slot index: " + std::to_string(index))
                                .c_str());
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
    uint32_t dataSize;
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;
    return_status status;

    auto it = find_if(spdmPool.begin(), spdmPool.end(), [&](spdmItem item) {
        return (item.pspdmContext == spdmContext);
    });
    if (it == spdmPool.end())
        return;

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
                zero_mem(&parameter, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
                *(uint32_t*)parameter.additional_data = sessionID;

                u8Value = 0;
                dataSize = sizeof(u8Value);
                status = libspdm_get_data(it->pspdmContext,
                                          LIBSPDM_DATA_SESSION_POLICY,
                                          &parameter, &u8Value, &dataSize);
                if (RETURN_ERROR(status))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Get session policy failed:" +
                         std::to_string(status))
                            .c_str());
                    break;
                }
                else
                {
                    phosphor::logging::log<phosphor::logging::level::DEBUG>(
                        ("SPDMResponderImpl::processSessionState session policy - " +
                         std::to_string(u8Value))
                            .c_str());
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
    if (spdmResponderCfg.version)
    {
        setCertificatePath(spdmResponderCfg.certPath);
        spdmTrans->setListener(
            std::bind(&SPDMResponderImpl::msgRecvCallback, this, _1, _2));
    }
}

} // namespace spdm_app_lib
