/**
 * Copyright © 2020 Intel Corporation
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
    void* pTmp = NULL;
    spdmResponderImpl* pspdmTmp = NULL;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == NULL)
        return false;
    pspdmTmp = static_cast<spdmResponderImpl*>(pTmp);
    return pspdmTmp->deviceSendMessage(spdmContext, requestSize, request,
                                       timeout);
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
    void* pTmp = NULL;
    spdmResponderImpl* pspdmTmp = NULL;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == NULL)
        return false;
    pspdmTmp = static_cast<spdmResponderImpl*>(pTmp);
    return pspdmTmp->deviceReceiveMessage(spdmContext, responseSize, response,
                                          timeout);
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
    void* pTmp = NULL;
    spdmResponderImpl* pspdmTmp = NULL;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == NULL)
        return;
    pspdmTmp = static_cast<spdmResponderImpl*>(pTmp);
    return pspdmTmp->processConnectionState(spdmContext, connectionState);
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
    void* pTmp = NULL;
    spdmResponderImpl* pspdmTmp = NULL;
    pTmp = libspdm_get_app_ptr_data(spdmContext);
    if (pTmp == NULL)
        return;
    pspdmTmp = static_cast<spdmResponderImpl*>(pTmp);
    return pspdmTmp->processSessionState(spdmContext, sessionID, sessionState);
}

/*Implement SPDMAppLib responder*/

/**
 * @brief Initial function of SPDM responder.
 *
 * The function will enter daemon mode. Accept request from assigned
 *trasport layer.
 *
 * @param  io                boost io_service object..
 * @param  trans             The pointer of transport instance.
 * @return 0: success, other: listed in spdmapplib::errorCodes
 **/
int spdmResponderImpl::initResponder(
    std::shared_ptr<boost::asio::io_service> io,
    std::shared_ptr<spdmtransport::spdmTransport> trans)
{
    using namespace std::placeholders;
    curIndex = 0;
    auto conn = std::make_shared<sdbusplus::asio::connection>(*io);
    pio = io;
    spdmResponderCfg =
        spdmapplib::getConfigurationFromEntityManager(conn, "SPDM_responder");
    if (spdmResponderCfg.version)
    {
        spdmTrans = trans;
        spdmTrans->initTransport(
            io, conn, std::bind(&spdmResponderImpl::addNewDevice, this, _1),
            std::bind(&spdmResponderImpl::removeDevice, this, _1),
            std::bind(&spdmResponderImpl::MsgRecvCallback, this, _1, _2));
    }
    else
    {
        std::cerr << __func__ << " getConfigurationFromEntityManager failed!"
                  << std::endl;
        return static_cast<int>(errorCodes::errGetCFG);
    }
    return 0;
}

/**
 * @brief Called when endpoint remove is detected.
 *
 * @param  ptransEP          The pointer to the removed endpoint object.
 * @return 0: success, other: failed.
 *
 **/
int spdmResponderImpl::removeDevice(void* ptransEndpoint)
{
    uint8_t i;
    for (i = 0; i < curIndex; i++)
    {
        if (matchDevice(
                &spdmPool[i].transEP,
                static_cast<spdmtransport::transportEndPoint*>(ptransEndpoint)))
            break;
    }
    if (i >= curIndex)
        return false;
    if (spdmPool[i].pspdmContext != NULL)
    {
        free(spdmPool[i].pspdmContext);
        spdmPool[i].pspdmContext = NULL;
    }
    spdmPool.erase(spdmPool.begin() + i);
    curIndex = curIndex - 1;
    return true;
}

/**
 * @brief Called when new endpoint detected.
 *
 * @param  ptransEP          The pointer to the new endpoint object.
 * @return 0: success, other: failed.
 *
 **/
int spdmResponderImpl::addNewDevice(void* ptransEndpoint)
{
    using namespace std::placeholders;

    spdmItem newItem;
    uint8_t newIndex;
    newItem.pspdmContext = (void*)malloc(libspdm_get_context_size());
    if (newItem.pspdmContext == NULL)
    {
        return false;
    }
    std::cerr << "addNewDevice" << std::endl;
    copyDevice(&newItem.transEP,
               static_cast<spdmtransport::transportEndPoint*>(ptransEndpoint));
    newItem.useSlotId = 0;
    newItem.sessonId = 0;
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
    libspdm_init_context(spdmPool[newIndex].pspdmContext);
    libspdm_register_device_io_func(spdmPool[newIndex].pspdmContext,
                                    responderDeviceSendMessage,
                                    responderDeviceReceiveMessage);
    libspdm_register_session_state_callback_func(
        spdmPool[newIndex].pspdmContext, spdmServerSessionStateCallback);
    libspdm_register_connection_state_callback_func(
        spdmPool[newIndex].pspdmContext, spdmServerConnectionStateCallback);

    libspdm_register_transport_layer_func(spdmPool[newIndex].pspdmContext,
                                          spdm_transport_none_encode_message,
                                          spdm_transport_none_decode_message);

    settingFromConfig(newIndex);
    return true;
}

/**
 * @brief Function to setup specific endpoint initial configuration.
 *
 * @param  ItemIndex      The endpoint index.
 * @return 0: success, other: failed.
 *
 **/
int spdmResponderImpl::settingFromConfig(uint8_t itemIndex)
{
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;   // Value that size is uint8_t
    uint16_t u16Value; // Value that size is uint16_t
    uint32_t u32Value; // Value that size is uint32_t
    void* tmpThis = static_cast<void*>(this);

    useSlotCount = static_cast<uint8_t>(spdmResponderCfg.slotcount);
    std::cerr << "Responder useSlotCount: " << spdmResponderCfg.slotcount
              << std::endl;

    memset(&parameter, 0, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter, &tmpThis,
                     sizeof(void*));

    u8Value = 0;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &parameter, &u8Value,
                     sizeof(u8Value));

    useResponderCapabilityFlags = spdmResponderCfg.capability;
    u32Value = useResponderCapabilityFlags;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter, &u32Value,
                     sizeof(u32Value));

    u8Value = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter, &u8Value,
                     sizeof(u8Value));

    u32Value = spdmResponderCfg.measHash;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter, &u32Value,
                     sizeof(u32Value));

    u32Value = spdmResponderCfg.asym;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &u32Value,
                     sizeof(u32Value));

    u16Value = (uint16_t)spdmResponderCfg.reqasym;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter, &u16Value,
                     sizeof(u16Value));

    u32Value = spdmResponderCfg.hash;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &u32Value,
                     sizeof(u32Value));

    u16Value = (uint16_t)spdmResponderCfg.dhe;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_DHE_NAME_GROUP, &parameter, &u16Value,
                     sizeof(u16Value));

    u16Value = (uint16_t)spdmResponderCfg.aead;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter, &u16Value,
                     sizeof(u16Value));

    u16Value = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &u16Value,
                     sizeof(u16Value));

    u8Value = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    libspdm_set_data(spdmPool[itemIndex].pspdmContext,
                     LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter, &u8Value,
                     sizeof(u8Value));

    return true;
}

/**
 * @brief Called when message received.
 *
 * @param  ptransEP      The pointer of the endpoint object to receive data.
 * @param  data          The vector of received data.
 * @return 0: success, other: failed.
 *
 **/
int spdmResponderImpl::addData(void* ptransEndpoint,
                               const std::vector<uint8_t>& data)
{
    uint8_t i;

    for (i = 0; i < curIndex; i++)
    {
        if (matchDevice(
                &spdmPool[i].transEP,
                static_cast<spdmtransport::transportEndPoint*>(ptransEndpoint)))
        {
            break;
        }
    }
    if (i >= curIndex)
        return false;

    spdmPool[i].data = data;
    return true;
}

/**
 * @brief Called when message received.
 *
 * The function is called in MsgRecvCallback to process incoming received
 *data.
 * @return 0: success, other: failed.
 *
 **/
int spdmResponderImpl::processSPDMMessage()
{
    uint8_t i;
    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].data.size() > 0)
        {
            libspdm_responder_dispatch_message(spdmPool[i].pspdmContext);
        }
    }
    fflush(stdout);
    return true;
}

/**
 * @brief Register to transport layer for handling received data.
 *
 * @param  ptransEP      The pointer of the endpoint object to receive data.
 * @param  data          The vector of received data.
 * @return 0: success, other: failed.
 *
 **/
int spdmResponderImpl::MsgRecvCallback(void* ptransEP,
                                       const std::vector<uint8_t>& data)
{
    addData(ptransEP, data);
    return processSPDMMessage();
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
return_status spdmResponderImpl::deviceReceiveMessage(void* spdmContext,
                                                      uintn* responseSize,
                                                      void* response,
                                                      uint64_t timeout)
{

    UNUSED(timeout);
    uint8_t i;

    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].pspdmContext == spdmContext)
            break;
    }
    if (i >= curIndex)
        return RETURN_DEVICE_ERROR;

    if (spdmPool[i].data.size() <= 1)
        return RETURN_DEVICE_ERROR;
    *responseSize = spdmPool[i].data.size() - 1;
    std::copy(spdmPool[i].data.begin() + 1, spdmPool[i].data.end(),
              (uint8_t*)response);
    spdmPool[i].data.clear();
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
return_status spdmResponderImpl::deviceSendMessage(void* spdmContext,
                                                   uintn requestSize,
                                                   const void* request,
                                                   uint64_t timeout)
{
    UNUSED(timeout);
    uint8_t i;
    for (i = 0; i < curIndex; i++)
    {
        if (spdmPool[i].pspdmContext == spdmContext)
            break;
    }
    if (i >= curIndex)
        return RETURN_DEVICE_ERROR;
    return spdmTrans->asyncSendData(&spdmPool[i].transEP, requestSize, request,
                                    timeout);
}

/**
 * @brief Register to libspdm for handling connection state change.
 *
 * @param  spdmContext      The pointer of the spdmcontext.
 * @param  connectionState  The connection state.
 *
 **/
void spdmResponderImpl::processConnectionState(
    void* spdmContext, libspdm_connection_state_t connectionState)
{
    void* data;
    uint32_t dataSize;
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;   // Value that size is uint8_t
    uint16_t u16Value; // Value that size is uint16_t
    uint32_t u32Value; // Value that size is uint32_t
    bool res;
    uint8_t index;
    spdm_version_number_t spdmVersion;
    uint8_t i;

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
                memset(&parameter, 0, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
                dataSize = sizeof(spdmVersion);
                libspdm_get_data(spdmPool[i].pspdmContext,
                                 LIBSPDM_DATA_SPDM_VERSION, &parameter,
                                 &spdmVersion, &dataSize);
                spdmPool[i].useVersion =
                    (uint8_t)(spdmVersion >> SPDM_VERSION_NUMBER_SHIFT_BIT);
            }
            /* Provision new content*/
            memset(&parameter, 0, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;

            dataSize = sizeof(u32Value);
            libspdm_get_data(spdmPool[i].pspdmContext,
                             LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                             &u32Value, &dataSize);
            spdmPool[i].useMeasurementHashAlgo = u32Value;
            dataSize = sizeof(u32Value);
            libspdm_get_data(spdmPool[i].pspdmContext,
                             LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter, &u32Value,
                             &dataSize);
            spdmPool[i].useAsymAlgo = u32Value;
            dataSize = sizeof(u32Value);
            libspdm_get_data(spdmPool[i].pspdmContext,
                             LIBSPDM_DATA_BASE_HASH_ALGO, &parameter, &u32Value,
                             &dataSize);
            spdmPool[i].useHashAlgo = u32Value;

            dataSize = sizeof(u16Value);
            libspdm_get_data(spdmPool[i].pspdmContext,
                             LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                             &u16Value, &dataSize);
            spdmPool[i].useReqAsymAlgo = u16Value;
            res = read_responder_public_certificate_chain(
                spdmPool[i].useHashAlgo, spdmPool[i].useAsymAlgo, &data,
                &dataSize, NULL, NULL);
            if (res)
            {
                memset(&parameter, 0, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                u8Value = useSlotCount;
                libspdm_set_data(spdmPool[i].pspdmContext,
                                 LIBSPDM_DATA_LOCAL_SLOT_COUNT, &parameter,
                                 &u8Value, sizeof(u8Value));

                for (index = 0; index < useSlotCount; index++)
                {
                    parameter.additional_data[0] = index;
                    libspdm_set_data(spdmPool[i].pspdmContext,
                                     LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
                                     &parameter, data, dataSize);
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
void spdmResponderImpl::processSessionState(
    void* spdmContext, uint32_t sessionID, libspdm_session_state_t sessionState)
{
    uint32_t dataSize;
    libspdm_data_parameter_t parameter;
    uint8_t u8Value;
    uint8_t i;

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
            spdmPool[i].sessonId = sessionID;
            if (spdmPool[i].useVersion >= SPDM_MESSAGE_VERSION_12)
            {
                memset(&parameter, 0, sizeof(parameter));
                parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
                *(uint32_t*)parameter.additional_data = sessionID;

                u8Value = 0;
                dataSize = sizeof(u8Value);
                libspdm_get_data(spdmPool[i].pspdmContext,
                                 LIBSPDM_DATA_SESSION_POLICY, &parameter,
                                 &u8Value, &dataSize);
                std::cerr << "session policy - 0x" << std::hex
                          << static_cast<uint16_t>(u8Value) << std::dec
                          << std::endl;
            }
            break;
        case LIBSPDM_SESSION_STATE_ESTABLISHED:
            // TODO
            // Pre created for some actions needed in this state in the future.
            break;
        default:
            ASSERT(false);
            break;
    }
}

/**
 * @brief Responder object create Factory function.
 *
 * @return Pointer to Responder implementation object.
 *
 **/
std::shared_ptr<spdmResponder> createResponder()
{
    return std::make_shared<spdmResponderImpl>();
}

} // namespace spdmapplib
