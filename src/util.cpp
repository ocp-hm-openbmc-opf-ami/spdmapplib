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

extern "C"
{
    /**
     * @brief dump hex data (called by libspdm)
     *
     * @param buffer : dump data
     * @param buffer_size: size of dump data
     */
    void libspdm_dump_hex_str(const uint8_t* buffer, size_t bufferSize)
    {
        for (size_t index = 0; index < bufferSize; index++)
        {
            printf(" %02x", buffer[index]);
        }
    }

    /**
     * @brief read cert file (called by libspdm)
     *
     * @param fileName : cert file
     * @param fileData (output): file content
     * @param fileSize (output): size of file content
     * @return  true: success, false: not able to read file.
     */
    bool libspdm_read_input_file(const char* fileName, void** fileData,
                                 size_t* fileSize)
    {
        std::string certPath = spdm_app_lib::getFilePath(fileName);
        FILE* fp = std::fopen(certPath.c_str(), "rb");
        if (!fp)
        {
            std::cerr << "Unable to open file" << certPath << "\n";
            *fileData = nullptr;
            return false;
        }
        std::fseek(fp, 0, SEEK_END);
        *fileSize = std::ftell(fp);

        *fileData = reinterpret_cast<void*>(malloc(*fileSize));
        if (nullptr == *fileData)
        {
            std::cerr << "No sufficient memory to allocate " << certPath
                      << "\n";
            std::fclose(fp);
            return false;
        }

        std::fseek(fp, 0, SEEK_SET);
        size_t tempResult = std::fread(*fileData, 1, *fileSize, fp);
        if (tempResult != *fileSize)
        {
            std::cerr << "Read input file error\n";
            free(reinterpret_cast<void*>(*fileData));
            std::fclose(fp);
            return false;
        }

        std::fclose(fp);
        return true;
    }
    /**
     * @brief dummy write file function(called by libspdm)
     *
     * @param fileName : cert file
     * @param fileData (output): file content
     * @param fileSize (output): size of file content
     * @return  true: success, false: not able to read file.
     */
    bool libspdm_write_output_file(const char* /*fileName*/,
                                   const void* /*fileData*/,
                                   size_t /*fileSize*/)
    {
        return true;
    }
}
