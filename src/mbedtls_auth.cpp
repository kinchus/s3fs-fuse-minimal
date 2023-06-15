/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Randy Rizun <rrizun@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include "mbedtls/md.h"     /* generic interface */
#include "mbedtls/md5.h"
#include "mbedtls/sha256.h" /* SHA-256 only */
#include <string>
#include <map>

#include "common.h"
#include "s3fs.h"
#include "s3fs_auth.h"
#include "s3fs_logger.h"

//-------------------------------------------------------------------
// Utility Function for version
//-------------------------------------------------------------------

const char* s3fs_crypt_lib_name()
{
    static const char version[] = "MbedTLS";

    return version;
}


//-------------------------------------------------------------------
// Utility Function for global init
//-------------------------------------------------------------------
bool s3fs_init_global_ssl()
{
    return true;
}

bool s3fs_destroy_global_ssl()
{
    return true;
}

//-------------------------------------------------------------------
// Utility Function for crypt lock
//-------------------------------------------------------------------
bool s3fs_init_crypt_mutex()
{
    return true;
}

bool s3fs_destroy_crypt_mutex()
{
    return true;
}

//-------------------------------------------------------------------
// Utility Function for HMAC
//-------------------------------------------------------------------

bool s3fs_HMAC(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
    if(!key || !data || !digest || !digestlen){
        return false;
    }
    *digest = new unsigned char[*digestlen + 1];
    if(!key || !data || !digest || !digestlen){
        return false;
    }
    *digest = new unsigned char[*digestlen + 1];
    const mbedtls_md_type_t alg = MBEDTLS_MD_SHA1;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(alg);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, (unsigned char *)key,keylen);
    mbedtls_md_hmac_update(&ctx, data, datalen);
    mbedtls_md_hmac_finish(&ctx, *digest);
    mbedtls_md_free(&ctx);
    return true;
    // return s3fs_HMAC_generic(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), key, keylen, data, datalen, digest, digestlen);
}


bool s3fs_HMAC256(const void* key, size_t keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
    if(!key || !data || !digest || !digestlen){
        return false;
    }
    *digest = new unsigned char[*digestlen + 1];
    const mbedtls_md_type_t alg = MBEDTLS_MD_SHA256;
    unsigned char out[MBEDTLS_MD_MAX_SIZE]; // safe but not optimal
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(alg);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, (unsigned char *)key,keylen);
    mbedtls_md_hmac_update(&ctx, data, datalen);
    mbedtls_md_hmac_finish(&ctx, *digest);
    mbedtls_md_free(&ctx);
    return true;
}


bool s3fs_HMAC_generic(const mbedtls_md_info_t *info, const void* key, unsigned long keylen, const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
    if(!key || !data || !digest || !digestlen){
        return false;
    }
    *digest = new unsigned char[*digestlen + 1];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, (unsigned char *)key,keylen);
    mbedtls_md_hmac_update(&ctx, data, datalen);
    mbedtls_md_hmac_finish(&ctx, *digest);
    mbedtls_md_free(&ctx);
    return true;
}
//-------------------------------------------------------------------
// Utility Function for MD5
//-------------------------------------------------------------------
size_t get_md5_digest_length()
{
    return MBEDTLS_MD_MAX_SIZE;
}


unsigned char* s3fs_md5_fd(int fd, off_t start, off_t size)
{
	mbedtls_md5_context ctx;
	off_t bytes;
    unsigned char* result;
    off_t len = 512;
    unsigned char buf[len];

    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            return NULL;
        }
        size = st.st_size;
    }

    mbedtls_md5_init(&ctx);
  	mbedtls_md5_starts(&ctx);

    for(off_t total = 0; total < size; total += bytes){


        bytes = len < (size - total) ? len : (size - total);
        bytes = pread(fd, buf, bytes, start + total);
        if(0 == bytes){
            // end of file
            break;
        }else if(-1 == bytes){
            // error
            S3FS_PRN_ERR("file read error(%d)", errno);
            mbedtls_md5_free(&ctx);
            return NULL;
        }
        mbedtls_md5_update(&ctx, buf, bytes);
    }
    mbedtls_md5_finish(&ctx, buf);
    result = new unsigned char[get_md5_digest_length()];
    memcpy(result, buf, get_md5_digest_length());
    mbedtls_md5_free(&ctx);
    return result;
}


//-------------------------------------------------------------------
// Utility Function for SHA256
//-------------------------------------------------------------------
size_t get_sha256_digest_length()
{
    return 32;
}


bool s3fs_sha256(const unsigned char* data, size_t datalen, unsigned char** digest, unsigned int* digestlen)
{
    size_t len = (*digestlen) = static_cast<unsigned int>(get_sha256_digest_length());
    *digest = new unsigned char[len];
    mbedtls_sha256(data, len, *digest, 0);
    return true;
}


unsigned char* s3fs_sha256_fd(int fd, off_t start, off_t size)
{
    off_t bytes;
    unsigned char* result;
    off_t buff_len = 512;
    unsigned char buf[buff_len];

    if(-1 == size){
        struct stat st;
        if(-1 == fstat(fd, &st)){
            return NULL;
        }
        size = st.st_size;
    }

    mbedtls_sha256_context ctx2;
    mbedtls_sha256_init(&ctx2);
    mbedtls_sha256_starts(&ctx2, 0); /* SHA-256, not 224 */

    for(off_t total = 0; total < size; total += bytes){
        bytes = buff_len < (size - total) ? buff_len : (size - total);
        bytes = pread(fd, buf, bytes, start + total);
        if(0 == bytes){
            // end of file
            break;
        }
        else if(-1 == bytes){
            // error
            S3FS_PRN_ERR("file read error(%d)", errno);
            mbedtls_sha256_free(&ctx2);
            return NULL;
        }
        mbedtls_sha256_update(&ctx2, buf, bytes);
    }

    mbedtls_sha256_finish(&ctx2, buf);
    result = new unsigned char[get_sha256_digest_length()];
    memcpy(result, buf, get_sha256_digest_length());
    mbedtls_sha256_free(&ctx2);

    return result;
}


/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
