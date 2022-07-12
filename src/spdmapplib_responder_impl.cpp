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
/**
 * @brief Register to libspdm for sending SPDM request payload.
 *
 * @param  spdmContext      The pointer of the spdmcontext.
 * @param  requestSize     The request payload size.
 * @param  request         The request data buffer pointer.
 * @param  timeout          The timeout time.
 * @return return_status defined in libspdm.
 *
 **/
return_status responderDeviceSendMessage(void* spdmContext, uintn requestSize,
                                         const void* request, uint64_t timeout)
{
    void* pTmp = nullptr;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == nullptr)
    {
        return errorcodes::generalReturnError;
    }
    SPDMResponderImpl* pspdmTmp = nullptr;
    pspdmTmp = static_cast<SPDMResponderImpl*>(pTmp);

    uint32_t j;
    std::vector<uint8_t> data;
    uint8_t* requestPayload = (uint8_t*)request;

    data.push_back(static_cast<uint8_t>(mctpw::MessageType::spdm));

    for (j = 0; j < requestSize; j++)
        data.push_back(*(requestPayload + j));

    return pspdmTmp->deviceSendMessage(spdmContext, data, timeout);
}

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
return_status responderDeviceReceiveMessage(void* spdmContext,
                                            uintn* responseSize, void* response,
                                            uint64_t timeout)
{
    void* pTmp = nullptr;
    return_status status;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == nullptr)
    {
        return errorcodes::generalReturnError;
    }
    SPDMResponderImpl* pspdmTmp = nullptr;
    pspdmTmp = static_cast<SPDMResponderImpl*>(pTmp);

    std::vector<uint8_t> rspData{};
    status = pspdmTmp->deviceReceiveMessage(spdmContext, rspData, timeout);
    *responseSize = rspData.size() - 1; // skip MessageType byte
    std::copy(rspData.begin() + 1, rspData.end(),
              reinterpret_cast<uint8_t*>(response));
    return status;
}

/**
 * @brief Register to libspdm for handling connection state change.
 *
 * @param  spdmContext      The pointer of the spdmcontext.
 * @param  connectionState  The connection state.
 *
 **/
void spdmServerConnectionStateCallback(
    void* spdmContext, libspdm_connection_state_t connectionState)
{
    void* pTmp = nullptr;
    SPDMResponderImpl* pspdmTmp = nullptr;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == nullptr)
    {
        return;
    }
    pspdmTmp = static_cast<SPDMResponderImpl*>(pTmp);
    pspdmTmp->processConnectionState(spdmContext, connectionState);
}
/**
 * @brief Register to libspdm for handling session state change.
 *
 * @param  spdmContext      The pointer of the spdmcontext.
 * @param  sessionID        The session ID.
 * @param  sessionState     The session state.
 *
 **/

void spdmServerSessionStateCallback(void* spdmContext, uint32_t sessionID,
                                    libspdm_session_state_t sessionState)
{
    void* pTmp = nullptr;
    SPDMResponderImpl* pspdmTmp = nullptr;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == nullptr)
        return;
    pspdmTmp = static_cast<SPDMResponderImpl*>(pTmp);
    return pspdmTmp->processSessionState(spdmContext, sessionID, sessionState);
}

/*Implement SPDMAppLib responder*/

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

/**
 * @brief Initial function of SPDM responder.
 *
 * The function will enter daemon mode. Accept request from assigned
 *transport layer.
 *
 * @param  ioc               The shared_ptr to boost io_context object..
 * @param  trans             The pointer of transport instance.
 * @return 0: success, other: listed in spdmapplib::errorCodes
 **/
int SPDMResponderImpl::initResponder(
    std::shared_ptr<boost::asio::io_context> ioc,
    std::shared_ptr<sdbusplus::asio::connection> conn,
    std::shared_ptr<spdmtransport::SPDMTransport> trans,
    SPDMConfiguration& spdmConfig)
{
    using namespace std::placeholders;
    curIndex = 0;
    pioc = ioc;
    spdmResponderCfg = spdmConfig;
    if (spdmResponderCfg.version)
    {
        setCertificatePath(spdmResponderCfg.certPath);

        spdmTrans = trans;
        spdmTrans->initTransport(
            ioc, conn, std::bind(&SPDMResponderImpl::addNewDevice, this, _1),
            std::bind(&SPDMResponderImpl::removeDevice, this, _1),
            std::bind(&SPDMResponderImpl::msgRecvCallback, this, _1, _2));
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "SPDMResponderImpl::initResponder getConfigurationFromEntityManager failed!");
        return errorcodes::spdmConfigurationNotFoundInEntityManager;
    }
    return RETURN_SUCCESS;
}

/**
 * @brief Called when endpoint remove is detected.
 *
 * @param  transEndpoint          The endpoint to be removed.
 * @return 0: success, other: failed.
 *
 **/
int SPDMResponderImpl::removeDevice(
    spdmtransport::TransportEndPoint& transEndpoint)
{
    uint8_t i;
    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].transEP == transEndpoint)
            break;
    }
    if (i >= curIndex)
    {
        return errorcodes::generalReturnError;
    }
    if (spdmPool[i].pspdmContext != nullptr)
    {
        free_pool(spdmPool[i].pspdmContext);
        spdmPool[i].pspdmContext = nullptr;
    }
    spdmPool.erase(spdmPool.begin() + i);
    curIndex = curIndex - 1;
    return RETURN_SUCCESS;
}

/**
 * @brief Called when new endpoint detected.
 *
 * @param  transEndpoint          The new endpoint object.
 * @return 0: success, other: failed.
 *
 **/
int SPDMResponderImpl::addNewDevice(
    spdmtransport::TransportEndPoint& transEndpoint)
{
    using namespace std::placeholders;

    for (auto& item : spdmPool)
    {
        if (item.transEP == transEndpoint)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(
                "SPDMResponderImpl::addNewDevice, Found old EP item, delete it.");
            removeDevice(transEndpoint);
        }
    }
    spdmItem newItem;
    uint8_t newIndex;
    return_status status;

    newItem.pspdmContext = allocate_zero_pool(libspdm_get_context_size());
    if (newItem.pspdmContext == nullptr)
    {
        return errorcodes::generalReturnError;
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
    newIndex = curIndex;
    curIndex++;
    status = libspdm_init_context(spdmPool[newIndex].pspdmContext);
    if (RETURN_ERROR(status))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SPDMResponderImpl::addNewDevice libspdm_init_context failed" +
             std::to_string(status))
                .c_str());
        return errorcodes::generalReturnError;
    }
    libspdm_register_device_io_func(spdmPool[newIndex].pspdmContext,
                                    responderDeviceSendMessage,
                                    responderDeviceReceiveMessage);
    libspdm_register_transport_layer_func(spdmPool[newIndex].pspdmContext,
                                          spdm_transport_none_encode_message,
                                          spdm_transport_none_decode_message);

    status = libspdm_register_session_state_callback_func(
        spdmPool[newIndex].pspdmContext, spdmServerSessionStateCallback);
    if (RETURN_ERROR(status))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SPDMResponderImpl::addNewDevice libspdm_register_session_state_callback_func failed" +
             std::to_string(status))
                .c_str());
        return errorcodes::generalReturnError;
    }
    status = libspdm_register_connection_state_callback_func(
        spdmPool[newIndex].pspdmContext, spdmServerConnectionStateCallback);
    if (RETURN_ERROR(status))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("SPDMResponderImpl::addNewDevice libspdm_register_connection_state_callback_func failed" +
             std::to_string(status))
                .c_str());
        return errorcodes::generalReturnError;
    }

    return settingFromConfig(newIndex);
}

/**
 * @brief Function to setup specific endpoint initial configuration.
 *
 * @param  ItemIndex      The endpoint index.
 * @return 0: success, other: failed.
 *
 **/
int SPDMResponderImpl::settingFromConfig(uint8_t itemIndex)
{
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;
    uint16_t u16Value;
    uint32_t u32Value;
    void* tmpThis = static_cast<void*>(this);
    return_status status;

    useSlotCount = static_cast<uint8_t>(spdmResponderCfg.slotcount);
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("SPDMResponderImpl::settingFromConfig Responder useSlotCount: " +
         std::to_string(spdmResponderCfg.slotcount))
            .c_str());

    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter,
                              &tmpThis, sizeof(void*));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    u8Value = 0;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    useResponderCapabilityFlags = spdmResponderCfg.capability;
    u32Value = useResponderCapabilityFlags;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    u8Value = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    u32Value = spdmResponderCfg.measHash;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    u32Value = spdmResponderCfg.asym;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    u16Value = (uint16_t)spdmResponderCfg.reqasym;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    u32Value = spdmResponderCfg.hash;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                              &u32Value, sizeof(u32Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    u16Value = (uint16_t)spdmResponderCfg.dhe;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    u16Value = (uint16_t)spdmResponderCfg.aead;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                              &u16Value, sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    u16Value = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &u16Value,
                              sizeof(u16Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    u8Value = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    status = libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                              LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                              &u8Value, sizeof(u8Value));
    if (RETURN_ERROR(status))
    {
        return errorcodes::libspdmReturnError;
    }

    return RETURN_SUCCESS;
}

/**
 * @brief Called when message received.
 *
 * @param  transEndpoint      The endpoint object to receive data.
 * @param  data          The vector of received data.
 * @return 0: success, other: failed.
 *
 **/
int SPDMResponderImpl::addData(spdmtransport::TransportEndPoint& transEndpoint,
                               const std::vector<uint8_t>& data)
{
    uint8_t i;

    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].transEP == transEndpoint)
        {
            break;
        }
    }
    if (i >= curIndex)
    {
        return errorcodes::generalReturnError;
    }
    spdmPool[i].data = std::move(data);
    return RETURN_SUCCESS;
}

/**
 * @brief Called when message received.
 *
 * The function is called in msgRecvCallback to process incoming received
 *data.
 * @return 0: success, other: failed.
 *
 **/
int SPDMResponderImpl::processSPDMMessage()
{
    uint8_t i;
    return_status status;
    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].data.size() > 0)
        {
            status =
                libspdm_responder_dispatch_message(spdmPool[i].pspdmContext);
            if (RETURN_ERROR(status))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("spdmRequesterImpl::setupResponder libspdm_responder_dispatch_message failed at: " +
                     std::to_string(i) + " status: " + std::to_string(status))
                        .c_str());
            }
        }
    }
    return RETURN_SUCCESS;
}

/**
 * @brief Register to transport layer for handling received data.
 *
 * @param  transEP      The endpoint object to receive data.
 * @param  data          The vector of received data.
 * @return 0: success, other: failed.
 *
 **/
int SPDMResponderImpl::msgRecvCallback(
    spdmtransport::TransportEndPoint& transEP, const std::vector<uint8_t>& data)
{
    addData(transEP, data);
    return processSPDMMessage();
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
return_status SPDMResponderImpl::deviceReceiveMessage(
    void* spdmContext, std::vector<uint8_t>& response, uint64_t /*timeout*/)
{
    uint8_t i;

    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].pspdmContext == spdmContext)
            break;
    }
    if (i >= curIndex)
        return RETURN_DEVICE_ERROR;

    response = std::move(spdmPool[i].data);
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        ("SPDMResponderImpl::deviceReceiveMessage responseSize: " +
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
return_status SPDMResponderImpl::deviceSendMessage(
    void* spdmContext, const std::vector<uint8_t>& request, uint64_t timeout)
{
    uint8_t i;
    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].pspdmContext == spdmContext)
            break;
    }
    if (i >= curIndex)
        return RETURN_DEVICE_ERROR;
    return spdmTrans->asyncSendData(spdmPool[i].transEP, request, timeout);
}

/**
 * @brief Register to libspdm for handling connection state change.
 *
 * @param  spdmContext      The pointer of the spdmcontext.
 * @param  connectionState  The connection state.
 *
 **/
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
    uint8_t i;
    return_status status;

    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].pspdmContext == spdmContext)
            break;
    }
    if (i >= curIndex)
        return;
    spdmPool[i].connectStatus = connectionState;
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
            if (spdmPool[i].useVersion == 0)
            {
                zero_mem(&parameter, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
                dataSize = sizeof(spdmVersion);
                status = libspdm_get_data(spdmPool[i].pspdmContext,
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
                spdmPool[i].useVersion =
                    (uint8_t)(spdmVersion >> SPDM_VERSION_NUMBER_SHIFT_BIT);
            }
            /* Provision new content*/
            zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

            dataSize = sizeof(u32Value);
            status = libspdm_get_data(spdmPool[i].pspdmContext,
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
            spdmPool[i].useMeasurementHashAlgo = u32Value;
            dataSize = sizeof(u32Value);
            status = libspdm_get_data(spdmPool[i].pspdmContext,
                                      LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                                      &u32Value, &dataSize);
            if (RETURN_ERROR(status))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Get AsymAlgo failed:" +
                     std::to_string(status))
                        .c_str());
                break;
            }
            spdmPool[i].useAsymAlgo = u32Value;
            dataSize = sizeof(u32Value);
            status = libspdm_get_data(spdmPool[i].pspdmContext,
                                      LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                                      &u32Value, &dataSize);
            if (RETURN_ERROR(status))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Get HashAlgo failed:" +
                     std::to_string(status))
                        .c_str());
                break;
            }
            spdmPool[i].useHashAlgo = u32Value;

            dataSize = sizeof(u16Value);
            status = libspdm_get_data(spdmPool[i].pspdmContext,
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
            spdmPool[i].useReqAsymAlgo = u16Value;
            res = read_responder_public_certificate_chain(
                spdmPool[i].useHashAlgo, spdmPool[i].useAsymAlgo, &data,
                &dataSize, nullptr, nullptr);
            if (res)
            {
                zero_mem(&parameter, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                u8Value = useSlotCount;
                status = libspdm_set_data(
                    spdmPool[i].pspdmContext, LIBSPDM_DATA_LOCAL_SLOT_COUNT,
                    &parameter, &u8Value, sizeof(u8Value));
                if (RETURN_ERROR(status))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        ("SPDMResponderImpl::processConnectionState LIBSPDM_CONNECTION_STATE_NEGOTIATED Set slotcount failed:" +
                         std::to_string(status))
                            .c_str());
                    break;
                }

                for (index = 0; index < useSlotCount; index++)
                {
                    parameter.additional_data[0] = index;
                    status =
                        libspdm_set_data(spdmPool[i].pspdmContext,
                                         LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
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

/**
 * @brief Register to libspdm for handling session state change.
 *
 * @param  spdmContext      The pointer of the spdmcontext.
 * @param  sessionID        The session ID.
 * @param  sessionState     The session state.
 *
 **/
void SPDMResponderImpl::processSessionState(
    void* spdmContext, uint32_t sessionID, libspdm_session_state_t sessionState)
{
    uint32_t dataSize;
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;
    uint8_t i;
    return_status status;

    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].pspdmContext == spdmContext)
            break;
    }
    if (i >= curIndex)
        return;

    switch (sessionState)
    {
        case LIBSPDM_SESSION_STATE_NOT_STARTED:
            // TODO
            // Pre created for some actions needed in this state in the future.
            break;
        case LIBSPDM_SESSION_STATE_HANDSHAKING:
            /* collect session policy*/
            spdmPool[i].sessionId = sessionID;
            if (spdmPool[i].useVersion >= SPDM_MESSAGE_VERSION_12)
            {
                zero_mem(&parameter, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
                *(uint32_t*)parameter.additional_data = sessionID;

                u8Value = 0;
                dataSize = sizeof(u8Value);
                status = libspdm_get_data(spdmPool[i].pspdmContext,
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

/**
 * @brief Responder object create Factory function.
 *
 * @return Pointer to Responder implementation object.
 *
 **/
std::shared_ptr<SPDMResponder> createResponder()
{
    return std::make_shared<SPDMResponderImpl>();
}

} // namespace spdmapplib
