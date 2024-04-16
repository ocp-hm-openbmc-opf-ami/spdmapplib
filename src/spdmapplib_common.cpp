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

#include "spdmapplib_common.hpp"

namespace spdm_app_lib
{
/* stores the certificate path */
std::string setCertPath{};
void* responderPrivateKeyData = nullptr;
size_t responderPrivateKeySize = 0;
constexpr uint8_t measSize = 48;
constexpr uint16_t ubootMeasStartIndex = 0x430;
constexpr uint16_t ubootMeasEndIndex = 0x460;
constexpr uint16_t fitImgMeasStartIndex = 0x4b0;
constexpr uint16_t fitImgMeasEndIndex = 0x4e0;
constexpr uint32_t spdmMctpHeaderSize = 0x1200;
constexpr uint32_t spdmTransportNoneHeaderSize = 0x1000;
constexpr uint32_t libspdmTransportHeaderSize = 64;
constexpr uint32_t libspdmTransportTailSize = 64;
constexpr uint32_t libspdmTransportAdditionalSize =
    (libspdmTransportHeaderSize + libspdmTransportTailSize);
constexpr uint32_t libspdmSenderBufferConst = 0x1100;
constexpr uint32_t libspdmReceiverBufferConst = 0x1200;
constexpr uint32_t libspdmSenderBufferSize =
    (libspdmSenderBufferConst + libspdmTransportAdditionalSize);
constexpr uint32_t libspdmReceiverBufferSize =
    (libspdmReceiverBufferConst + libspdmTransportAdditionalSize);
std::array<uint8_t, measSize> ubootMeas;
std::array<uint8_t, measSize> fitImgMeas;

/* Required by libspdm for send/recv payload*/
bool sendReceiveBufferAcquired = false;
size_t sendReceiveBufferSize(0);
std::array<uint8_t, libspdmReceiverBufferSize> sendReceiveBuffer;

std::string getFilePath(const char* fileName)
{
    static std::string pfmLocation = "/dev/mtd/pfm";
    if (std::string(fileName) == pfmLocation)
    {
        return std::string(fileName);
    }
    std::string path = setCertPath + "/" + std::string(fileName);
    return path;
}

void setCertificatePath(std::string& certPath)
{
    setCertPath = certPath;
}

void libspdmRegisterDeviceBuffer(void* spdmContext)
{
    libspdm_register_device_buffer_func(
        spdmContext, libspdmSenderBufferSize, libspdmReceiverBufferSize,
        spdmDeviceAcquireSenderBuffer, spdmDeviceReleaseSenderBuffer,
        spdmDeviceAcquireReceiverBuffer, spdmDeviceReleaseReceiverBuffer);
}

void freeSpdmContext(spdmItem& spdm)
{
    freeAllocatedMemory(spdm.scratchBuffer);
    freeAllocatedMemory(spdm.spdmContext);
    freeAllocatedMemory(spdm.certChain);
    freeAllocatedMemory(spdm.rootCert);
    spdm.data.clear();
    spdm.dataCert.clear();
    spdm.dataMeas.clear();
}

void freeAllocatedMemory(void*& memory)
{
    if (memory)
    {
        free_pool(memory);
    }
    memory = nullptr;
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
    spdm_version_number_t spdmVersion;

    spdmVersion = static_cast<uint8_t>(spdmConfig.version)
                  << SPDM_VERSION_NUMBER_SHIFT_BIT;
    if (!spdmSetData(spdm, LIBSPDM_DATA_SPDM_VERSION, spdmVersion, parameter))
    {
        return false;
    }
    if (!spdmSetData(spdm, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, u8Value,
                     parameter))
    {
        return false;
    }

    u8Value = LIBSPDM_SPDM_10_11_VERIFY_SIGNATURE_ENDIAN_BIG_OR_LITTLE;
    if (!spdmSetData(spdm,
                     LIBSPDM_DATA_SPDM_VERSION_10_11_VERIFY_SIGNATURE_ENDIAN,
                     u8Value, parameter))
    {
        return false;
    }

    if (!spdmSetData(spdm, LIBSPDM_DATA_CAPABILITY_FLAGS, spdmConfig.capability,
                     parameter))
    {
        return false;
    }

    u8Value = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
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
              const std::string transport,
              libspdm_device_send_message_func sendMessage,
              libspdm_device_receive_message_func recvMessage)
{
    spdm.spdmContext = allocate_zero_pool(libspdm_get_context_size());
    if (spdm.spdmContext == nullptr)
    {
        return false;
    }
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

    if (transport == "mctp")
    {
        libspdm_register_transport_layer_func(
            spdm.spdmContext, spdmMctpHeaderSize, libspdmTransportHeaderSize,
            libspdmTransportTailSize, libspdm_transport_mctp_encode_message,
            libspdm_transport_mctp_decode_message);
    }
    else
    {
        libspdm_register_transport_layer_func(
            spdm.spdmContext, spdmTransportNoneHeaderSize, 0, 0,
            spdm_transport_none_encode_message,
            spdm_transport_none_decode_message);
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
    libspdmRegisterDeviceBuffer(spdm.spdmContext);
    libspdm_set_scratch_buffer(spdm.spdmContext, spdm.scratchBuffer,
                               scratchBufferSize);

    return true;
}

std::vector<uint8_t> formSendMessage(size_t requestSize, const void* request)
{
    uint8_t* requestPayload =
        reinterpret_cast<uint8_t*>(const_cast<void*>(request));
    std::vector<uint8_t> data{};
    for (size_t j = 0; j < requestSize; j++)
    {
        data.push_back(*(requestPayload + j));
    }
    return data;
}

void formRecvMessage(size_t* responseSize, void** response,
                     const std::vector<uint8_t> payload)
{
    *responseSize = payload.size();
    std::copy(payload.begin(), payload.end(),
              reinterpret_cast<uint8_t*>(*response));
}

libspdm_return_t spdmDeviceAcquireSenderBuffer(void* /*context*/,
                                               void** msg_buf_ptr)
{
    LIBSPDM_ASSERT(!sendReceiveBufferAcquired);
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
                                                 void** msg_buf_ptr)
{
    LIBSPDM_ASSERT(!sendReceiveBufferAcquired);
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

bool fillBMCMeasurements()
{
    void* data = nullptr;
    size_t fileSize = 0;
    bool result = false;
    static std::string pfmLocation = "/dev/mtd/pfm";
    result = libspdm_read_input_file(pfmLocation.c_str(), &data, &fileSize);
    if (!result)
    {
        free(data);
        return result;
    }
    std::copy(std::next(reinterpret_cast<uint8_t*>(data), ubootMeasStartIndex),
              std::next(reinterpret_cast<uint8_t*>(data), ubootMeasEndIndex),
              ubootMeas.begin());
    std::copy(std::next(reinterpret_cast<uint8_t*>(data), fitImgMeasStartIndex),
              std::next(reinterpret_cast<uint8_t*>(data), fitImgMeasEndIndex),
              fitImgMeas.begin());
    free(data);
    return result;
}

bool getMeasforIndex(uint8_t* measurement, const uint8_t measurementIndex)
{
    constexpr uint32_t ubootMeasIndex = 0x01;
    constexpr uint32_t fitImgMeasIndex = 0x02;
    if (measurementIndex == ubootMeasIndex)
    {
        if (ubootMeas.empty())
        {
            return false;
        }
        std::copy(ubootMeas.begin(), ubootMeas.end(), measurement);
        return true;
    }
    else if (measurementIndex == fitImgMeasIndex)
    {
        if (fitImgMeas.empty())
        {
            return false;
        }
        std::copy(fitImgMeas.begin(), fitImgMeas.end(), measurement);
        return true;
    }
    return false;
}

bool fetchResponderPrivateKey()
{
    if (!libspdm_read_responder_private_key(
            SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
            &responderPrivateKeyData, &responderPrivateKeySize))
    {
        return false;
    }
    return true;
}

bool assignResponderPrivateKey(void** privateKey, size_t* privateKeySize)
{
    if (responderPrivateKeyData == nullptr || responderPrivateKeySize == 0)
    {
        return false;
    }
    *privateKeySize = responderPrivateKeySize;
    *privateKey = reinterpret_cast<void*>(malloc(*privateKeySize));
    if (nullptr == *privateKey)
    {
        return false;
    }
    std::memcpy(*privateKey, responderPrivateKeyData, *privateKeySize);
    return true;
}

void destroyPrivateKey()
{
    if (responderPrivateKeyData == nullptr || responderPrivateKeySize == 0)
    {
        return;
    }
    libspdm_zero_mem(responderPrivateKeyData, responderPrivateKeySize);
    free_pool(responderPrivateKeyData);
    responderPrivateKeySize = 0;
}
} // namespace spdm_app_lib
