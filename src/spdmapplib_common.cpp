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

void freeSpdmContext(spdmItem& spdm)
{
    free_pool(spdm.spdmContext);
    spdm.spdmContext = nullptr;
    spdm.data.clear();
    spdm.dataCert.clear();
    spdm.dataMeas.clear();
}

bool validateSpdmRc(return_status status)
{
    if (RETURN_ERROR(status))
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
    uint32_t dataSize = 0;
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
    zero_mem(&parameter, sizeof(parameter));
    static constexpr std::array<libspdm_data_location_t, 4> locationMap{
        LIBSPDM_DATA_LOCATION_CONNECTION, LIBSPDM_DATA_LOCATION_LOCAL,
        LIBSPDM_DATA_LOCATION_SESSION, LIBSPDM_DATA_LOCATION_MAX};
    parameter.location = locationMap[opReq];
}

bool spdmInit(spdmItem& spdm, const spdm_transport::TransportEndPoint& transEP,
              const std::string transport,
              libspdm_device_send_message_func sendMessage,
              libspdm_device_receive_message_func recvMessage)
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
    auto encodeCB = (transport == "mctp")
                        ? libspdm_transport_mctp_encode_message
                        : spdm_transport_none_encode_message;
    auto decodeCB = (transport == "mctp")
                        ? libspdm_transport_mctp_decode_message
                        : spdm_transport_none_decode_message;
    libspdm_register_device_io_func(spdm.spdmContext, sendMessage, recvMessage);

    libspdm_register_transport_layer_func(spdm.spdmContext, encodeCB, decodeCB);
    return true;
}

std::vector<uint8_t> formSendMessage(uintn requestSize, const void* request)
{
    uint8_t* requestPayload =
        reinterpret_cast<uint8_t*>(const_cast<void*>(request));
    std::vector<uint8_t> data{};
    for (uint32_t j = 0; j < requestSize; j++)
    {
        data.push_back(*(requestPayload + j));
    }
    return data;
}

void formRecvMessage(uintn* responseSize, void* response,
                     const std::vector<uint8_t> payload)
{
    *responseSize = payload.size();
    std::copy(payload.begin(), payload.end(),
              reinterpret_cast<uint8_t*>(response));
}
} // namespace spdm_app_lib