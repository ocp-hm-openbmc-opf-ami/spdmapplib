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

/* OP-TEE TEE client API (built by optee_client) */
#include "spdm_self_test.hpp"

#include <tee_client_api.h>

#include <phosphor-logging/log.hpp>

#include <cstring>
#include <iostream>

namespace spdm_self_test
{
#define TA_SPDM_UUID                                                           \
    {                                                                          \
        0xd9857be1, 0x0162, 0x4d2b,                                            \
        {                                                                      \
            0x8c, 0x77, 0xe4, 0x2a, 0x04, 0x7f, 0x62, 0x22                     \
        }                                                                      \
    }

#define TA_SELF_TEST 0

bool getMbedTLSFIPSStatus(bool& status, std::string& mbedtlsVersion)
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_SPDM_UUID;
    uint32_t err_origin;

    /* Initialize a context connecting us to the TEE */
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "TEEC_InitializeContext");
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("TEEC_InitializeContext failed with code" + std::to_string(res))
                .c_str());

        return false;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>("TEEC_OpenSession");
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
                           &err_origin);
    if (res != TEEC_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("TEEC_InitializeContext failed with code" + std::to_string(res))
                .c_str());
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("TEEC_InitializeContext failed with origin" +
             std::to_string(err_origin))
                .c_str());

        TEEC_FinalizeContext(&ctx);

        return false;
    }

    /* Clear the TEEC_Operation struct */
    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_TEMP_INOUT,
                                     TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = -1;

    char buffer[64];
    op.params[1].tmpref.buffer = buffer;
    op.params[1].tmpref.size = sizeof(buffer);

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "TEEC_InvokeCommand TA_SELF_TEST");

    res = TEEC_InvokeCommand(&sess, TA_SELF_TEST, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("TEEC_InvokeCommand failed with code" + std::to_string(res))
                .c_str());
        phosphor::logging::log<phosphor::logging::level::ERR>(
            ("TEEC_InvokeCommand failed with origin" +
             std::to_string(err_origin))
                .c_str());

        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "TEEC_CloseSession");
        TEEC_CloseSession(&sess);

        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "TEEC_FinalizeContext");
        TEEC_FinalizeContext(&ctx);

        return false;
    }

    if (op.params[0].value.a == 1)
    {
        mbedtlsVersion = (char*)op.params[1].tmpref.buffer;
        status = true;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "TEEC_CloseSession");
    TEEC_CloseSession(&sess);

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "TEEC_FinalizeContext");
    TEEC_FinalizeContext(&ctx);

    return true;
}
} // namespace spdm_self_test
