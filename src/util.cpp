/**
 * Copyright © 20220 Intel Corporation
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

#include "spdmapplib_impl.hpp"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <iostream>
char* setCertPath = NULL;

extern "C"
{
    /**
     * @brief dump hex data (called by libspdm)
     *
     * @param buffer : dump data
     * @param buffer_size: size of dump data
     */
    void dump_hex_str(const uint8_t* buffer, uint32_t bufferSize)
    {
        uint32_t index;

        for (index = 0; index < bufferSize; index++)
        {
            printf(" %02x", buffer[index]);
        }
    }

    /**
     * @brief read cert file (called by libspdm)
     *
     * @param file_name : cert file
     * @param file_data (output): file content
     * @param file_size (output): size of file content
     * @return  true: success, false: not able to read file.
     */
    bool read_input_file(const char* fileName, void** fileData,
                         uint32_t* fileSize)
    {
        FILE* fp;
        uint32_t tempResult;
        char newFileName[256];

        if (setCertPath != NULL)
            sprintf(newFileName, "%s/%s", setCertPath, fileName);
        else
            sprintf(newFileName, "%s", fileName);
        if ((fp = fopen(newFileName, "rb")) == NULL)
        {
            printf("Unable to open file %s\n", newFileName);
            *fileData = NULL;
            return false;
        }

        fseek(fp, 0, SEEK_END);
        *fileSize = ftell(fp);

        *fileData = (void*)malloc(*fileSize);
        if (NULL == *fileData)
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
     * @brief set cert file Path
     *
     * @param certPath : cert file location
     * @return true: success, false: not a valide path.
     */
    bool setCertificatePath(char* certPath)
    {
        if (certPath)
        {
            setCertPath = certPath;
            return true;
        }
        else
        {
            return false;
        }
    }
}
