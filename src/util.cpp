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
        FILE* fp;
        size_t tempResult;
        char* setCerPath = nullptr;
        char newFileName[256];
        char* pfmLoc = "/dev/mtd/pfm";

        if (!strcmp(pfmLoc, fileName))
        {
            sprintf(newFileName, "%s", fileName);
        }
        else
        {
            setCerPath = spdm_app_lib::getCertificatePath();
            if (setCerPath != nullptr)
                sprintf(newFileName, "%s/%s", setCerPath, fileName);
            else
                sprintf(newFileName, "%s", fileName);
        }
        if ((fp = fopen(newFileName, "rb")) == nullptr)
        {
            printf("Unable to open file %s\n", newFileName);
            *fileData = nullptr;
            return false;
        }

        fseek(fp, 0, SEEK_END);
        *fileSize = ftell(fp);

        *fileData = (void*)malloc(*fileSize);
        if (nullptr == *fileData)
        {
            printf("No sufficient memory to allocate %s\n", fileName);
            fclose(fp);
            return false;
        }

        fseek(fp, 0, SEEK_SET);
        tempResult = fread(*fileData, 1, *fileSize, fp);
        if (tempResult != *fileSize)
        {
            printf("Read input file error %s", fileName);
            free((void*)*fileData);
            fclose(fp);
            return false;
        }

        fclose(fp);

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
