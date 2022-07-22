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
