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

/**
 * This file contains declaration of base 64 encode and decode fucntions.
 */

#pragma once
#include <string>
namespace spdm_self_test
{

/**
 * @brief Get MbedTLS FIPS status
 *
 * @param   status           MbedTLS self-test APIs pass/fail status
 * @param   mbedtlsVersion   Get mbedTLS version
 * @return  true             Indicates Success for communication status between spdmapplib and spdm-ta
 * @return  false            Indicates Failure for communication status between spdmapplib and spdm-ta
 **/
bool getMbedTLSFIPSStatus(bool& status, std::string& mbedtlsVersion);
} // namespace spdm_self_test
