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
 
#pragma once
namespace spdm_app_lib
{
/**
 * @brief spdmapplib error codes list.
 *
 */

namespace error_codes
{
inline constexpr int generalReturnError = -1;
inline constexpr int returnSuccess = 0;
inline constexpr int spdmConfigurationNotFoundInEntityManager = 1;
inline constexpr int libspdmReturnError =
    2; // libspdm function calls return error.
} // namespace error_codes
} // namespace spdm_app_lib
