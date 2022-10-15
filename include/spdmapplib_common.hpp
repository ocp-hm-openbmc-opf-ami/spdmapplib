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
 * limitations under the License.
 */
#pragma once

#include "spdmapplib.hpp"

#include <phosphor-logging/log.hpp>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iostream>
// clang-format off
extern "C"
{
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_responder_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "library/malloclib.h"
#include "library/spdm_transport_none_lib.h"
}
// clang-format on

namespace spdm_app_lib
{
/*Common Functions used across Requester and Responder */
inline constexpr int operationGet = 0;
inline constexpr int operationSet = 1;
inline constexpr int operationSession = 2;

inline constexpr uint32_t exeConnectionVersionOnly = 0x1;
inline constexpr uint32_t exeConnectionDigest = 0x2;
inline constexpr uint32_t exeConnectionCert = 0x4;
inline constexpr uint32_t exeConnectionChal = 0x8;
inline constexpr uint32_t exeConnectionMeas = 0x10;
inline constexpr uint32_t exeConnection =
    (exeConnectionDigest | exeConnectionCert | exeConnectionChal |
     exeConnectionMeas);
/**
 * @brief SPDM device context structure
 *
 */
typedef struct
{
    void* spdmContext;
    void* scratchBuffer;
    spdm_transport::TransportEndPoint transEP;
    uint8_t useSlotId;
    uint32_t sessionId;
    uint32_t useVersion;
    uint16_t useReqAsymAlgo;
    uint32_t useMeasurementHashAlgo;
    uint32_t useAsymAlgo;
    uint32_t useHashAlgo;
    libspdm_connection_state_t connectStatus;
    std::vector<uint8_t> data;
    std::vector<uint8_t> dataCert;
    std::vector<uint8_t> dataMeas;
} spdmItem;

/**
 * @brief get cert file Path
 *
 * @return pointer to certPath
 */
char* getCertificatePath();

/**
 * @brief set cert file Path
 *
 * @param certPath : cert file location
 */
void setCertificatePath(std::string& certPath);

/**
 * @brief Register SPDM device buffer management functions.
 * This function must be called after libspdm_init_context,
 * and before any SPDM communication.
 *
 * @param  spdmContext   A pointer to the SPDM context.
 **/
void libspdmRegisterDeviceBuffer(void* spdmContext);

/**
 * @brief freeSpdmContext deallocates spdm context
 *
 * @param spdm      spdmItem having context
 */
void freeSpdmContext(spdmItem& spdm);

/**
 * @brief validateSpdmRc checks the return status from libspdm
 *
 * @param status
 * @return true     if return status is Success
 * @return false    if return status is failure
 */
bool validateSpdmRc(libspdm_return_t status);

/**
 * @brief getSPDMAppContext get spdm app context
 *
 * @param spdmContext       spdmContext returned by libspdm
 * @param spdmAppContext    spdmAppContext to be obtained
 * @return true             when spdmAppContext fetched successfully
 * @return false            failure to get spdmAppContext
 */
bool getSPDMAppContext(void* spdmContext, void*& spdmAppContext);

/**
 * @brief spdmSetConfigData performs libspdm_set_data
 *
 * @param spdm          spdmItem having context
 * @param spdmConfig    config passed from application
 * @return true         when setting config is successful
 * @return false        when setting config fails
 */
bool spdmSetConfigData(spdmItem& spdm, SPDMConfiguration& spdmConfig);

/**
 * @brief spdmGetAlgo gets values of Negotiated Algos
 *
 * @param spdm          spdmItem having context
 * @param measHash      Measurement Hash Value
 * @param baseAsym      Base Asym value
 * @param baseHash      Base Hash value
 * @param reqBaseAsym   Req Base Hash value
 * @return true         when Algo value is fetched successfully
 * @return false        when fetching algo value fails
 */
bool spdmGetAlgo(spdmItem& spdm, uint32_t& measHash, uint32_t& baseAsym,
                 uint32_t& baseHash, uint16_t& reqBaseAsym);

/**
 * @brief initGetSetParameter inits libspdm_get_data/libspdm_set_data parameter
 *
 * @param parameter     libspdm_data_parameter_t from libspdm
 * @param opReq         indicates GET/SET operation
 */
void initGetSetParameter(libspdm_data_parameter_t& parameter, uint8_t opReq);

/**
 * @brief spdmInit inits the context,registers callback with libspdm
 *
 * @param spdm          spdmItem having context
 * @param transEP       endPoint id
 * @param transport     underlying transport
 * @param sendMessage   sendMessage Callback
 * @param recvMessage   recvMessage callback
 * @return true         when init is successful
 * @return false        when init fails
 */
bool spdmInit(spdmItem& spdm, const spdm_transport::TransportEndPoint& transEP,
              const std::string transport,
              libspdm_device_send_message_func sendMessage,
              libspdm_device_receive_message_func recvMessage);

/**
 * @brief spdmGetData performs libspdm_get_data
 *
 * @tparam T            template with possible(uint8_t, uint16, uint32)
 * @param spdm          spdmItem having context
 * @param configType    indicates the config type
 * @param configData    contains the required data
 * @param parameter     libspdm_data_parameter_t
 * @return true         when libspdm_get_data is successful
 * @return false        when libspdm_get_data fails
 */
template <typename T>
bool spdmGetData(spdmItem& spdm, libspdm_data_type_t configType, T& configData,
                 libspdm_data_parameter_t parameter)
{
    T data;
    size_t data_size = sizeof(data);

    if (!validateSpdmRc(libspdm_get_data(spdm.spdmContext, configType,
                                         &parameter, &data, &data_size)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (" libspdm_get_data Failed for Config Type!- " +
             std::to_string(configType))
                .c_str());
        return false;
    }
    configData = data;
    return true;
}

/**
 * @brief spdmGetData performs libspdm_set_data
 *
 * @tparam T            template with possible(uint8_t, uint16, uint32)
 * @param spdm          spdmItem having context
 * @param configType    indicates the config type
 * @param configData    contains the required data
 * @param parameter     libspdm_data_parameter_t
 * @return true         when libspdm_set_data is successful
 * @return false        when libspdm_set_data is fails
 */
template <typename T>
bool spdmSetData(spdmItem& spdm, libspdm_data_type_t configType, T configData,
                 libspdm_data_parameter_t parameter)
{
    if (!validateSpdmRc(libspdm_set_data(spdm.spdmContext, configType,
                                         &parameter, &configData,
                                         sizeof(configData))))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (" libspdm_set_data Failed for Config Type!- " +
             std::to_string(configType))
                .c_str());
        return false;
    }
    return true;
}

/**
 * @brief  Acquires transport layer sender buffer
 *
 * @param  context     Pointer to the SPDM context.
 * @param  maxMsgSize  Maximum size of sender buffer.
 * @param  msgBufPtr   Pointer to a sender buffer.
 * @retval RETURN_SUCCESS  The sender buffer is acquired.
 * @retval RETURN_DEVICE_ERROR       A device error occurs when the SPDM message
 *is received from the device.
 * @retval RETURN_INVALID_PARAMETER  The message is NULL, message_size is NULL
 *or the *message_size is zero.
 * @retval RETURN_TIMEOUT            A timeout occurred while waiting for the
 *SPDM message to execute.
 **/
libspdm_return_t spdmDeviceAcquireSenderBuffer(void* context,
                                               size_t* maxMsgSize,
                                               void** msgBufPtr);

/**
 * @brief Release transport layer sender buffer
 *
 * @param  context     A pointer to the SPDM context.
 * @param  msgBufPtr   A pointer to a sender buffer.
 **/
void spdmDeviceReleaseSenderBuffer(void* context, const void* msgBufPtr);

/**
 * @brief Acquires transport layer receiver buffer
 *
 * @param  spdmContext    A pointer to the SPDM context.
 * @param  messageSize    size in bytes of the message data buffer.
 * @param  message        A pointer to a destination buffer to store the
 *message.
 *
 * @retval RETURN_SUCCESS            The SPDM message is received successfully.
 * @retval RETURN_DEVICE_ERROR       A device error occurs when the SPDM message
 *is received from the device.
 * @retval RETURN_INVALID_PARAMETER  The message is NULL, message_size is NULL
 *or the *message_size is zero.
 * @retval RETURN_TIMEOUT            A timeout occurred while waiting for the
 *SPDM message to execute.
 **/
libspdm_return_t spdmDeviceAcquireReceiverBuffer(void* context,
                                                 size_t* maxMsgSize,
                                                 void** msgBufPtr);

/**
 * Release transport layer receiver buffer
 *
 * @param  context    A pointer to the SPDM context.
 * @param  msgBufPtr  A pointer to a receiver buffer.
 **/
void spdmDeviceReleaseReceiverBuffer(void* context, const void* msgBufPtr);

} // namespace spdm_app_lib
