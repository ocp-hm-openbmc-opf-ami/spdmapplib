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
#include "spdmapplib_common.hpp"

namespace spdm_app_lib
{
/* stores the certificate path */
std::string setCertPath{};

char* getCertificatePath()
{
    return const_cast<char*>(setCertPath.c_str());
}

void setCertificatePath(std::string& certPath)
{
    setCertPath = certPath;
}

/**
 * @brief libspdm register proxy function.
 * @param spdm_context
 **/
void libspdmRegisterDeviceBuffer(void* spdmContext)
{
    libspdm_register_device_buffer_func(
        spdmContext, libspdm_external_apis::spdmDeviceAcquireSenderBuffer,
        libspdm_external_apis::spdmDeviceReleaseSenderBuffer,
        libspdm_external_apis::spdmDeviceAcquireReceiverBuffer,
        libspdm_external_apis::spdmDeviceReleaseReceiverBuffer);
}

void freeSpdmContext(spdmItem& spdm)
{
    free_pool(spdm.scratchBuffer);
    spdm.scratchBuffer = nullptr;
    free_pool(spdm.spdmContext);
    spdm.spdmContext = nullptr;
    spdm.data.clear();
    spdm.dataCert.clear();
    spdm.dataMeas.clear();
}

bool validateSpdmRc(libspdm_return_t status)
{
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            (" libspdm return status Error!- " + std::to_string(status))
                .c_str());
        return false;
    }
    return true;
}

bool getSPDMAppContext(void* spdmContext, void*& spdmAppContext)
{
    size_t dataSize = 0;
    libspdm_data_parameter_t parameter;
    initGetSetParameter(parameter, spdm_app_lib::operationGet);
    dataSize = sizeof(dataSize);
    return validateSpdmRc(
        libspdm_get_data(spdmContext, LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter,
                         &spdmAppContext, &dataSize));
}

bool spdmSetConfigData(spdmItem& spdm, SPDMConfiguration& spdmConfig)
{
    uint8_t u8Value = 0;
    uint16_t u16Value = 0;
    libspdm_data_parameter_t parameter;
    initGetSetParameter(parameter, operationSet);

    if (!spdmSetData(spdm, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, u8Value,
                     parameter))
    {
        return false;
    }

    if (!spdmSetData(spdm, LIBSPDM_DATA_CAPABILITY_FLAGS, spdmConfig.capability,
                     parameter))
    {
        return false;
    }

    u8Value = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    if (!spdmSetData(spdm, LIBSPDM_DATA_MEASUREMENT_SPEC, u8Value, parameter))
    {
        return false;
    }

    if (!spdmSetData(spdm, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
                     spdmConfig.measHash, parameter))
    {
        return false;
    }

    if (!spdmSetData(spdm, LIBSPDM_DATA_BASE_ASYM_ALGO, spdmConfig.asym,
                     parameter))
    {
        return false;
    }

    if (!spdmSetData(spdm, LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
                     static_cast<uint16_t>(spdmConfig.reqasym), parameter))
    {
        return false;
    }

    if (!spdmSetData(spdm, LIBSPDM_DATA_BASE_HASH_ALGO, spdmConfig.hash,
                     parameter))
    {
        return false;
    }

    if (!spdmSetData(spdm, LIBSPDM_DATA_DHE_NAME_GROUP,
                     static_cast<uint16_t>(spdmConfig.dhe), parameter))
    {
        return false;
    }

    if (!spdmSetData(spdm, LIBSPDM_DATA_AEAD_CIPHER_SUITE,
                     static_cast<uint16_t>(spdmConfig.aead), parameter))
    {
        return false;
    }

    u16Value = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
    if (!spdmSetData(spdm, LIBSPDM_DATA_KEY_SCHEDULE, u16Value, parameter))
    {
        return false;
    }

    u8Value = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;
    if (!spdmSetData(spdm, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, u8Value,
                     parameter))
    {
        return false;
    }
    return true;
}

bool spdmGetAlgo(spdmItem& spdm, uint32_t& measHash, uint32_t& baseAsym,
                 uint32_t& baseHash, uint16_t& reqBaseAsym)
{
    libspdm_data_parameter_t parameter;
    initGetSetParameter(parameter, operationGet);
    if (!spdmGetData(spdm, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, measHash,
                     parameter))
    {
        return false;
    }

    if (!spdmGetData(spdm, LIBSPDM_DATA_BASE_ASYM_ALGO, baseAsym, parameter))
    {
        return false;
    }

    if (!spdmGetData(spdm, LIBSPDM_DATA_BASE_HASH_ALGO, baseHash, parameter))
    {
        return false;
    }

    if (!spdmGetData(spdm, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, reqBaseAsym,
                     parameter))
    {
        return false;
    }
    return true;
}

void initGetSetParameter(libspdm_data_parameter_t& parameter, uint8_t opReq)
{
    libspdm_zero_mem(&parameter, sizeof(parameter));
    static constexpr std::array<libspdm_data_location_t, 4> locationMap{
        LIBSPDM_DATA_LOCATION_CONNECTION, LIBSPDM_DATA_LOCATION_LOCAL,
        LIBSPDM_DATA_LOCATION_SESSION, LIBSPDM_DATA_LOCATION_MAX};
    parameter.location = locationMap[opReq];
}

bool spdmInit(spdmItem& spdm, const spdm_transport::TransportEndPoint& transEP,
              libspdm_device_send_message_func sendMessage,
              libspdm_device_receive_message_func recvMessage,
              libspdm_transport_encode_message_func encodeCB,
              libspdm_transport_decode_message_func decodeCB,
              libspdm_transport_get_header_size_func headerSizeCB)
{
    spdm.spdmContext = allocate_zero_pool(libspdm_get_context_size());
    if (spdm.spdmContext == nullptr)
    {
        return false;
    }
    spdm.useSlotId = 0;
    spdm.sessionId = 0;
    spdm.useVersion = 0;
    spdm.useReqAsymAlgo = 0;
    spdm.useMeasurementHashAlgo = 0;
    spdm.useAsymAlgo = 0;
    spdm.useHashAlgo = 0;
    spdm.transEP = transEP;
    spdm.connectStatus = LIBSPDM_CONNECTION_STATE_NOT_STARTED;
    spdm.data.clear();
    spdm.dataCert.clear();
    spdm.dataMeas.clear();

    if (!validateSpdmRc(libspdm_init_context(spdm.spdmContext)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "spdmInit libspdm_init_context Failed!");
        return false;
    }

    size_t scratchBufferSize =
        libspdm_get_sizeof_required_scratch_buffer(spdm.spdmContext);
    spdm.scratchBuffer = allocate_zero_pool(scratchBufferSize);
    if (spdm.scratchBuffer == nullptr)
    {
        free_pool(spdm.spdmContext);
        spdm.spdmContext = nullptr;
        return false;
    }

    libspdm_register_device_io_func(spdm.spdmContext, sendMessage, recvMessage);

    libspdm_register_transport_layer_func(spdm.spdmContext, encodeCB, decodeCB,
                                          headerSizeCB);

    libspdmRegisterDeviceBuffer(spdm.spdmContext);
    libspdm_set_scratch_buffer(spdm.spdmContext, spdm.scratchBuffer,
                               scratchBufferSize);

    return true;
}

namespace libspdm_external_apis
{
bool sendReceiveBufferAcquired = false;
size_t sendReceiveBufferSize;
std::array<uint8_t, LIBSPDM_SENDER_RECEIVE_BUFFER_SIZE> sendReceiveBuffer;
libspdm_return_t spdmDeviceAcquireSenderBuffer(void* /*context*/,
                                               size_t* max_msg_size,
                                               void** msg_buf_ptr)
{
    LIBSPDM_ASSERT(!sendReceiveBufferAcquired);
    *max_msg_size = sendReceiveBuffer.size();
    *msg_buf_ptr = &sendReceiveBuffer;
    std::fill_n(sendReceiveBuffer.begin(), sendReceiveBuffer.size(), 0);
    sendReceiveBufferAcquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdmDeviceReleaseSenderBuffer(void* /*context*/, const void* msg_buf_ptr)
{
    LIBSPDM_ASSERT(sendReceiveBufferAcquired);
    LIBSPDM_ASSERT(msg_buf_ptr == &sendReceiveBuffer);
    sendReceiveBufferAcquired = false;
    return;
}

libspdm_return_t spdmDeviceAcquireReceiverBuffer(void* /*context*/,
                                                 size_t* max_msg_size,
                                                 void** msg_buf_ptr)
{
    LIBSPDM_ASSERT(!sendReceiveBufferAcquired);
    *max_msg_size = sendReceiveBuffer.size();
    *msg_buf_ptr = &sendReceiveBuffer;
    std::fill_n(sendReceiveBuffer.begin(), sendReceiveBuffer.size(), 0);
    sendReceiveBufferAcquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdmDeviceReleaseReceiverBuffer(void* /*context*/, const void* msg_buf_ptr)
{
    LIBSPDM_ASSERT(sendReceiveBufferAcquired);
    LIBSPDM_ASSERT(msg_buf_ptr == &sendReceiveBuffer);
    sendReceiveBufferAcquired = false;
    return;
}
} // namespace libspdm_external_apis

} // namespace spdm_app_lib
