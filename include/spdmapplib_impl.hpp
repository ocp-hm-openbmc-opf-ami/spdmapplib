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
// clang-format off
extern "C"
{
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_responder_lib.h"
#include "spdm_device_secret_lib_internal.h"
#include "library/malloclib.h"
}
// clang-format on

inline constexpr uint32_t exeConnectionVersionOnly = 0x1;
inline constexpr uint32_t exeConnectionDigest = 0x2;
inline constexpr uint32_t exeConnectionCert = 0x4;
inline constexpr uint32_t exeConnectionChal = 0x8;
inline constexpr uint32_t exeConnectionMeas = 0x10;
inline constexpr uint32_t exeConnection =
    (exeConnectionDigest | exeConnectionCert | exeConnectionChal |
     exeConnectionMeas);

namespace spdm_app_lib
{
/**
 * @brief SPDM device context structure
 *
 */
typedef struct
{
    void* pspdmContext;
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

/*Utility function*/
/**
 * @brief set cert file Path
 *
 * @param certPath : cert file location
 */
void setCertificatePath(std::string& certPath);

} // namespace spdm_app_lib
