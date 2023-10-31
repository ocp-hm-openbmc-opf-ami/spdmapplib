/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/
#include <base.h>
#if defined(_MSC_VER) || (defined(__clang__) && (defined (LIBSPDM_CPU_AARCH64) || \
    defined(LIBSPDM_CPU_ARM)))
#else
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/stat.h>
#endif
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "library/memlib.h"
#include "include/spdm_bmc_secret_lib.h"

/* "LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY = 1" means use the RAW private key only
 * "LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY = 0" means controled by g_private_key_mode
 **/
#define LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY 0
/* "g_private_key_mode = 1" means use the PEM mode
 * "g_private_key_mode = 0" means use the RAW mode
 **/
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
bool g_private_key_mode = 1;
#endif


#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
bool libspdm_read_responder_private_key(uint32_t base_asym_algo,
                                        void **data, size_t *size)
{
    bool res;
    char *file;

    switch (base_asym_algo) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        file = "sm2/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        file = "ed25519/end_responder.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        file = "ed448/end_responder.key";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}
#endif

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
bool libspdm_read_requester_private_key(uint16_t req_base_asym_alg,
                                        void **data, size_t *size)
{
    bool res;
    char *file;

    switch (req_base_asym_alg) {
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
        file = "rsa2048/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
        file = "rsa3072/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096:
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096:
        file = "rsa4096/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
        file = "ecp256/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
        file = "ecp384/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521:
        file = "ecp521/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256:
        file = "sm2/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519:
        file = "ed25519/end_requester.key";
        break;
    case SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448:
        file = "ed448/end_requester.key";
        break;
    default:
        LIBSPDM_ASSERT(false);
        return false;
    }
    res = libspdm_read_input_file(file, data, size);
    return res;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP
bool libspdm_read_cached_requester_info(uint32_t base_asym_algo,
                                        uint8_t **req_info, size_t *req_info_length)
{
    return false;
}

bool libspdm_cache_requester_info(uint32_t base_asym_algo,
                                  uint8_t *req_info, size_t req_info_length)
{
    return false;
}

bool libspdm_read_cached_csr(uint32_t base_asym_algo, uint8_t **csr_pointer, size_t *csr_len)
{
    return false;
}

bool libspdm_gen_csr(uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
                     uint8_t *requester_info, size_t requester_info_length,
                     size_t *csr_len, uint8_t **csr_pointer)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_GET_CSR_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
/**
 * Fill image hash measurement block.
 *
 * @return measurement block size.
 **/
void libspdm_fill_measurement(size_t start_index, size_t end_index, uint8_t *meas,
                      uint8_t *meas_data) {
    size_t fill = 0;
    size_t index = start_index;
    for (; index < end_index; index++, fill++) {
        meas_data[fill] = meas[index];
    }
}

/**
 * Fill BMC measurement block.
 *
 * @return measurement block size.
 **/
size_t libspdm_fill_bmc_fw_measurement_hash(bool use_bit_stream,
                                uint32_t measurement_hash_algo,
                                uint8_t measurements_index,
                                spdm_measurement_block_dmtf_t *measurement_block)
{
    size_t hash_size;
    bool result;
    const char *file = "/dev/mtd/pfm";
    uint8_t *data;
    size_t size;
    uint8_t measurement_hash_data[SHA384_SIZE];

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);

    measurement_block->measurement_block_common_header.index = measurements_index;
    measurement_block->measurement_block_common_header.measurement_specification =
                                    SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;

    libspdm_set_mem(measurement_hash_data, sizeof(measurement_hash_data), (uint8_t)(measurements_index));

    if (!use_bit_stream) {
        measurement_block->measurement_block_dmtf_header
            .dmtf_spec_measurement_value_type =
            0 | SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MUTABLE_FIRMWARE;
        measurement_block->measurement_block_dmtf_header
            .dmtf_spec_measurement_value_size = (uint16_t)hash_size;

        measurement_block->measurement_block_common_header.measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       (uint16_t)hash_size);

        result = libspdm_read_input_file(file, (void **)&data, &size);
        if (!result) {
          return false;
        }
        if (measurements_index == BMC_UBOOT_MEAS_INDEX) {
            libspdm_fill_measurement(BMC_UBOOT_MEAS_START_INDEX, BMC_UBOOT_MEAS_END_INDEX,
                           data, measurement_hash_data);
        } else if (measurements_index == BMC_FITIMG_MEAS_INDEX) {
            libspdm_fill_measurement(BMC_FITIMG_MEAS_START_INDEX, BMC_FITIMG_MEAS_END_INDEX,
                           data, measurement_hash_data);
        } else {
            free(data);
            data = NULL;
            return false;
        }
        uint8_t *hash_value = (uint8_t *)(measurement_block + 1);
        libspdm_copy_mem(hash_value, sizeof(measurement_hash_data),
                   measurement_hash_data, sizeof(measurement_hash_data));
        free(data);

        return sizeof(spdm_measurement_block_dmtf_t) + hash_size;
    } else {
        measurement_block->measurement_block_dmtf_header
            .dmtf_spec_measurement_value_type =
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MUTABLE_FIRMWARE |
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
        measurement_block->measurement_block_dmtf_header
            .dmtf_spec_measurement_value_size = (uint16_t)sizeof(measurement_hash_data);

        measurement_block->measurement_block_common_header.measurement_size =
            (uint16_t)(sizeof(spdm_measurement_block_dmtf_header_t) +
                       (uint16_t)sizeof(measurement_hash_data));

        uint8_t *hash_value = (uint8_t *)(measurement_block + 1);
        libspdm_copy_mem(hash_value, sizeof(measurement_hash_data), measurement_hash_data,
                   sizeof(measurement_hash_data));

        return sizeof(spdm_measurement_block_dmtf_t) + sizeof(measurement_hash_data);
    }
}

libspdm_return_t libspdm_measurement_collection(
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurements_index,
    uint8_t request_attribute,
    uint8_t *content_changed,
    uint8_t *measurements_count,
    void *measurements,
    size_t *measurements_size)
{
    spdm_measurement_block_dmtf_t *measurement_block;
    size_t hash_size;
    uint8_t index;
    size_t total_size_needed;
    bool use_bit_stream;
    size_t measurement_block_size;

    if ((measurement_specification !=
         SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) ||
        (measurement_hash_algo == 0)) {
        return LIBSPDM_STATUS_UNSUPPORTED_CAP;
    }

    hash_size = libspdm_get_measurement_hash_size(measurement_hash_algo);
    LIBSPDM_ASSERT(hash_size != 0);

    use_bit_stream = false;
    if ((measurement_hash_algo == SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY) ||
        ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED) !=
         0)) {
        use_bit_stream = true;
    }

    if (measurements_index ==
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
        *measurements_count = LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER;
        goto successful_return;
    } else if (measurements_index ==
               SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {

        /* Calculate total_size_needed based on hash algo selected.
         * If we have an hash algo, then the first HASH_NUMBER elements will be
         * hash values, otherwise HASH_NUMBER raw bitstream values.*/
        if (!use_bit_stream) {
            total_size_needed =
                LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                (sizeof(spdm_measurement_block_dmtf_t) + hash_size);
        } else {
            total_size_needed =
                LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER *
                (sizeof(spdm_measurement_block_dmtf_t) + LIBSPDM_MEASUREMENT_RAW_DATA_SIZE);
        }

        LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
        if (total_size_needed > *measurements_size) {
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        *measurements_size = total_size_needed;
        *measurements_count = LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER;
        measurement_block = measurements;

        /* The first HASH_NUMBER blocks may be hash values or raw bitstream*/
        for (index = 1; index <= LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER; index++) {
            measurement_block_size = libspdm_fill_bmc_fw_measurement_hash (use_bit_stream,
                                                                            measurement_hash_algo,
                                                                            index,
                                                                            measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
            measurement_block = (void *)((uint8_t *)measurement_block + measurement_block_size);
        }
        goto successful_return;
    } else {
        /* One Index */
        if (measurements_index <= LIBSPDM_MEASUREMENT_BLOCK_HASH_NUMBER) {
            if (!use_bit_stream) {
                total_size_needed =
                    sizeof(spdm_measurement_block_dmtf_t) +
                    hash_size;
            } else {
                total_size_needed =
                    sizeof(spdm_measurement_block_dmtf_t) +
                    LIBSPDM_MEASUREMENT_RAW_DATA_SIZE;
            }
            LIBSPDM_ASSERT(total_size_needed <= *measurements_size);
            if (total_size_needed > *measurements_size) {
                return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
            }

            *measurements_count = 1;
            *measurements_size = total_size_needed;

            measurement_block = measurements;
            measurement_block_size = libspdm_fill_bmc_fw_measurement_hash (use_bit_stream,
                                                                            measurement_hash_algo,
                                                                            measurements_index,
                                                                            measurement_block);
            if (measurement_block_size == 0) {
                return LIBSPDM_STATUS_MEAS_INTERNAL_ERROR;
            }
        } else {
            *measurements_count = 0;
            return LIBSPDM_STATUS_MEAS_INVALID_INDEX;
        }
    }

successful_return:
    if ((content_changed != NULL) &&
        ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_12)) {
        /* return content change*/
        if ((request_attribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
            0) {
            *content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED;
        } else {
            *content_changed = SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_NO_DETECTION;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}

bool libspdm_generate_measurement_summary_hash(
    spdm_version_number_t spdm_version, uint32_t base_hash_algo,
    uint8_t measurement_specification, uint32_t measurement_hash_algo,
    uint8_t measurement_summary_hash_type,
    uint8_t *measurement_summary_hash,
    size_t *measurement_summary_hash_size)
{
    uint8_t measurement_data[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    size_t index;
    spdm_measurement_block_dmtf_t *cached_measurment_block;
    size_t measurment_data_size;
    size_t measurment_block_size;
    uint8_t device_measurement[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
    uint8_t device_measurement_count;
    size_t device_measurement_size;
    libspdm_return_t status;
    bool result;

    switch (measurement_summary_hash_type) {
    case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
        break;

    case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
    case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:
        if (*measurement_summary_hash_size != libspdm_get_hash_size(base_hash_algo)) {
            return false;
        }

        /* get all measurement data*/
        device_measurement_size = sizeof(device_measurement);
        status = libspdm_measurement_collection(
            spdm_version, measurement_specification,
            measurement_hash_algo,
            0xFF, /* Get all measurements*/
            0,
            NULL,
            &device_measurement_count, device_measurement,
            &device_measurement_size);
        if (LIBSPDM_STATUS_IS_ERROR(status)) {
            return false;
        }

        /* double confirm that MeasurmentData internal size is correct*/
        measurment_data_size = 0;
        cached_measurment_block = (void *)device_measurement;
        for (index = 0; index < device_measurement_count; index++) {
            measurment_block_size =
                sizeof(spdm_measurement_block_common_header_t) +
                cached_measurment_block
                ->measurement_block_common_header
                .measurement_size;
            LIBSPDM_ASSERT(cached_measurment_block
                           ->measurement_block_common_header
                           .measurement_size ==
                           sizeof(spdm_measurement_block_dmtf_header_t) +
                           cached_measurment_block
                           ->measurement_block_dmtf_header
                           .dmtf_spec_measurement_value_size);
            measurment_data_size +=
                cached_measurment_block
                ->measurement_block_common_header
                .measurement_size;
            cached_measurment_block =
                (void *)((size_t)cached_measurment_block +
                         measurment_block_size);
        }

        LIBSPDM_ASSERT(measurment_data_size <=
                       LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE);

        /* get required data and hash them*/
        cached_measurment_block = (void *)device_measurement;
        measurment_data_size = 0;
        for (index = 0; index < device_measurement_count; index++) {
            measurment_block_size =
                sizeof(spdm_measurement_block_common_header_t) +
                cached_measurment_block
                ->measurement_block_common_header
                .measurement_size;
            /* filter unneeded data*/
            if ((measurement_summary_hash_type ==
                 SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH) ||
                ((cached_measurment_block
                  ->measurement_block_dmtf_header
                  .dmtf_spec_measurement_value_type &
                  SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK) ==
                 SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM)) {
                if (spdm_version < (SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT)) {
                    libspdm_copy_mem(&measurement_data[measurment_data_size],
                                     sizeof(measurement_data)
                                     - (&measurement_data[measurment_data_size] - measurement_data),
                                     &cached_measurment_block->measurement_block_dmtf_header,
                                     cached_measurment_block->measurement_block_common_header
                                     .measurement_size);

                    measurment_data_size +=
                        cached_measurment_block
                        ->measurement_block_common_header
                        .measurement_size;
                } else {
                    libspdm_copy_mem(&measurement_data[measurment_data_size],
                                     sizeof(measurement_data)
                                     - (&measurement_data[measurment_data_size] - measurement_data),
                                     cached_measurment_block,
                                     sizeof(cached_measurment_block->measurement_block_common_header) +
                                     cached_measurment_block->measurement_block_common_header
                                     .measurement_size);

                    measurment_data_size +=
                        sizeof(cached_measurment_block->measurement_block_common_header) +
                        cached_measurment_block
                        ->measurement_block_common_header
                        .measurement_size;
                }
            }
            cached_measurment_block =
                (void *)((size_t)cached_measurment_block +
                         measurment_block_size);
        }

        result = libspdm_hash_all(base_hash_algo, measurement_data,
                                  measurment_data_size, measurement_summary_hash);
        if (!result) {
            return false;
        }
        break;
    default:
        return false;
        break;
    }
    return true;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
bool libspdm_requester_data_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context;
    bool result;

#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
    if (g_private_key_mode) {
        void *private_pem;
        size_t private_pem_size;

        result = libspdm_read_requester_private_key(
            req_base_asym_alg, &private_pem, &private_pem_size);
        if (!result) {
            return false;
        }

        result = libspdm_req_asym_get_private_key_from_pem(req_base_asym_alg,
                                                           private_pem,
                                                           private_pem_size, NULL,
                                                           &context);
        if (!result) {
            free(private_pem);
            return false;
        }

        if (is_data_hash) {
            result = libspdm_req_asym_sign_hash(spdm_version, op_code, req_base_asym_alg,
                                                base_hash_algo, context,
                                                message, message_size, signature, sig_size);
        } else {
            result = libspdm_req_asym_sign(spdm_version, op_code, req_base_asym_alg,
                                           base_hash_algo, context,
                                           message, message_size,
                                           signature, sig_size);
        }
        libspdm_req_asym_free(req_base_asym_alg, context);
        free(private_pem);
    }
#endif
    return result;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

bool libspdm_responder_data_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context;
    bool result;
#if !LIBSPDM_PRIVATE_KEY_MODE_RAW_KEY_ONLY
    if (g_private_key_mode) {
        void *private_pem;
        size_t private_pem_size;

        result = libspdm_read_responder_private_key(
            base_asym_algo, &private_pem, &private_pem_size);
        if (!result) {
            return false;
        }

        result = libspdm_asym_get_private_key_from_pem(
            base_asym_algo, private_pem, private_pem_size, NULL, &context);
        if (!result) {
            free(private_pem);
            return false;
        }

        if (is_data_hash) {
            result = libspdm_asym_sign_hash(spdm_version, op_code, base_asym_algo, base_hash_algo,
                                            context,
                                            message, message_size, signature, sig_size);
        } else {
            result = libspdm_asym_sign(spdm_version, op_code, base_asym_algo,
                                       base_hash_algo, context,
                                       message, message_size,
                                       signature, sig_size);
        }
        libspdm_asym_free(base_asym_algo, context);
        free(private_pem);
    }
#endif
    return result;
}

#if LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP
uint8_t m_libspdm_my_zero_filled_buffer[64];
uint8_t m_libspdm_bin_str0[0x11] = {
    0x00, 0x00, /* length - to be filled*/
    /* SPDM_VERSION_1_1_BIN_CONCAT_LABEL */
    0x73, 0x70, 0x64, 0x6d, 0x31, 0x2e, 0x31, 0x20,
    /* SPDM_BIN_STR_0_LABEL */
    0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64,
};

bool libspdm_psk_handshake_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size,
    uint8_t *out, size_t out_size)
{
    void *psk;
    size_t psk_size;
    size_t hash_size;
    bool result;
    uint8_t handshake_secret[64];

    if (psk_hint_size == 0) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
    } else if ((strcmp((const char *)psk_hint, LIBSPDM_TEST_PSK_HINT_STRING) ==
                0) &&
               (psk_hint_size == sizeof(LIBSPDM_TEST_PSK_HINT_STRING))) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
    } else {
        return false;
    }
    printf("[PSK]: ");
    libspdm_dump_hex_str(psk, psk_size);
    printf("\n");

    hash_size = libspdm_get_hash_size(base_hash_algo);

    result = libspdm_hkdf_extract(base_hash_algo, psk, psk_size, m_libspdm_my_zero_filled_buffer,
                                  hash_size, handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_expand(base_hash_algo, handshake_secret, hash_size,
                                 info, info_size, out, out_size);
    libspdm_zero_mem(handshake_secret, hash_size);

    return result;
}

bool libspdm_psk_master_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size, uint8_t *out,
    size_t out_size)
{
    void *psk;
    size_t psk_size;
    size_t hash_size;
    bool result;
    uint8_t handshake_secret[64];
    uint8_t salt1[64];
    uint8_t master_secret[64];

    if (psk_hint_size == 0) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
    } else if ((strcmp((const char *)psk_hint, LIBSPDM_TEST_PSK_HINT_STRING) ==
                0) &&
               (psk_hint_size == sizeof(LIBSPDM_TEST_PSK_HINT_STRING))) {
        psk = LIBSPDM_TEST_PSK_DATA_STRING;
        psk_size = sizeof(LIBSPDM_TEST_PSK_DATA_STRING);
    } else {
        return false;
    }

    hash_size = libspdm_get_hash_size(base_hash_algo);

    result = libspdm_hkdf_extract(base_hash_algo, psk, psk_size, m_libspdm_my_zero_filled_buffer,
                                  hash_size, handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    *(uint16_t *)m_libspdm_bin_str0 = (uint16_t)hash_size;
    /* patch the version*/
    m_libspdm_bin_str0[6] = (char)('0' + ((spdm_version >> 12) & 0xF));
    m_libspdm_bin_str0[8] = (char)('0' + ((spdm_version >> 8) & 0xF));
    result = libspdm_hkdf_expand(base_hash_algo, handshake_secret, hash_size,
                                 m_libspdm_bin_str0, sizeof(m_libspdm_bin_str0), salt1,
                                 hash_size);
    libspdm_zero_mem(handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_extract(base_hash_algo, m_libspdm_my_zero_filled_buffer,
                                  hash_size, salt1, hash_size, master_secret, hash_size);
    libspdm_zero_mem(salt1, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_expand(base_hash_algo, master_secret, hash_size,
                                 info, info_size, out, out_size);
    libspdm_zero_mem(master_secret, hash_size);

    return result;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_EX_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP
bool libspdm_write_certificate_to_nvm(uint8_t slot_id, const void * cert_chain,
                                      size_t cert_chain_size)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERTIFICATE_CAP */
