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
#if defined(_WIN32) || (defined(__clang__) && (defined (LIBSPDM_CPU_AARCH64) || \
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

bool g_in_trusted_environment = false;

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

bool libspdm_get_responder_private_key_from_raw_data(uint32_t base_asym_algo, void **context)
{
    return false;
}

bool libspdm_get_requester_private_key_from_raw_data(uint32_t base_asym_algo, void **context)
{
    return false;
}

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
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

bool libspdm_read_responder_public_key(uint32_t base_asym_algo,
                                       void **data, size_t *size)
{
    return false;
}

bool libspdm_read_requester_public_key(uint16_t req_base_asym_alg,
                                       void **data, size_t *size)
{
    return false;
}

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
bool libspdm_read_cached_last_csr_request(uint8_t **last_csr_request, size_t *last_csr_request_len)
{
    return false;
}

bool libspdm_cache_last_csr_request(const uint8_t *last_csr_request, size_t last_csr_request_len)
{
    return false;
}

/*
 * return true represent that: the device complete the csr by reset successfuly
 * return false represent that: the device complete the csr need reset
 **/
bool libspdm_read_cached_csr(uint8_t **csr_pointer, size_t *csr_len)
{
    return false;
}

bool libspdm_gen_csr(uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
                     const void *request, size_t request_size,
                     uint8_t *requester_info, size_t requester_info_length,
                     uint8_t *opaque_data, uint16_t opaque_data_length,
                     size_t *csr_len, uint8_t *csr_pointer,
                     bool is_device_cert_model)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */

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

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
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
                                    SPDM_MEASUREMENT_SPECIFICATION_DMTF;

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
         SPDM_MEASUREMENT_SPECIFICATION_DMTF) ||
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
        *measurements_count = LIBSPDM_MEASUREMENT_BLOCK_NUMBER;
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
        *measurements_count = LIBSPDM_MEASUREMENT_BLOCK_NUMBER;
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

size_t libspdm_secret_lib_meas_opaque_data_size;

bool libspdm_measurement_opaque_data(
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_index,
    uint8_t request_attribute,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_meas_opaque_data_size <= *opaque_data_size);

    *opaque_data_size = libspdm_secret_lib_meas_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}

size_t libspdm_secret_lib_challenge_opaque_data_size;

bool libspdm_challenge_opaque_data(
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *measurement_summary_hash,
    size_t measurement_summary_hash_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    size_t index;

    LIBSPDM_ASSERT(libspdm_secret_lib_challenge_opaque_data_size <= *opaque_data_size);

    *opaque_data_size = libspdm_secret_lib_challenge_opaque_data_size;

    for (index = 0; index < *opaque_data_size; index++)
    {
        ((uint8_t *)opaque_data)[index] = (uint8_t)index;
    }

    return true;
}

bool libspdm_encap_challenge_opaque_data(
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *measurement_summary_hash,
    size_t measurement_summary_hash_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    return false;
}

bool libspdm_generate_measurement_summary_hash(
    spdm_version_number_t spdm_version, uint32_t base_hash_algo,
    uint8_t measurement_specification, uint32_t measurement_hash_algo,
    uint8_t measurement_summary_hash_type,
    uint8_t *measurement_summary_hash,
    uint32_t measurement_summary_hash_size)
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
        if (measurement_summary_hash_size != libspdm_get_hash_size(base_hash_algo)) {
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
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

bool libspdm_responder_data_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    void *context = NULL;
    bool result = false;

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
            libspdm_zero_mem(private_pem, private_pem_size);
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
        libspdm_zero_mem(private_pem, private_pem_size);
        free(private_pem);
    }
    return result;
}

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP
bool libspdm_psk_handshake_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size,
    uint8_t *out, size_t out_size)
{
    return false;
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
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
bool libspdm_is_in_trusted_environment()
{
    return g_in_trusted_environment;
}

bool libspdm_write_certificate_to_nvm(uint8_t slot_id, const void * cert_chain,
                                      size_t cert_chain_size,
                                      uint32_t base_hash_algo, uint32_t base_asym_algo)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */
