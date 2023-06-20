/*
 * s3fs - FUSE-based file system backed by Amazon S3
 *
 * Copyright(C) 2007 Takeshi Nakatani <ggtakec.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <cstdio>

#include <string>

#include "common.h"
#include "s3fs_help.h"
#include "s3fs_auth.h"

//-------------------------------------------------------------------
// Contents
//-------------------------------------------------------------------
static const char help_string[] = 
    "\n"
    "Mount an Amazon S3 bucket as a file system.\n"
    "\n"
    "Usage:\n"
    "   mounting\n"
    "     s3fs bucket[:/path] mountpoint [options]\n"
    "     s3fs mountpoint [options (must specify bucket= option)]\n"
    "\n"
    "   unmounting\n"
    "     umount mountpoint\n"
    "\n"
    "   General forms for s3fs and FUSE/mount options:\n"
    "      -o opt[,opt...]\n"
    "      -o opt [-o opt] ...\n"
    "\n"
    "   utility mode (remove interrupted multipart uploading objects)\n"
    "     s3fs --incomplete-mpu-list (-u) bucket\n"
    "     s3fs --incomplete-mpu-abort[=all | =<date format>] bucket\n"
    "\n"
    "s3fs Options:\n"
    "\n"
    "   Most s3fs options are given in the form where \"opt\" is:\n"
    "\n"
    "             <option_name>=<option_value>\n"
    "\n"
    "   bucket\n"
    "      - if it is not specified bucket name (and path) in command line,\n"
    "        must specify this option after -o option for bucket name.\n"
    "\n"
    "   default_acl (default=\"private\")\n"
#if S3FS_EXTRAS
    "      - the default canned acl to apply to all written s3 objects,\n"
    "        e.g., private, public-read. see\n"
    "        https://docs.aws.amazon.com/AmazonS3/latest/dev/acl-overview.html#canned-acl\n"
    "        for the full list of canned ACLs\n"
    "\n"
#endif
    "   retries (default=\"5\")\n"
#if S3FS_EXTRAS
    "      - number of times to retry a failed S3 transaction\n"
    "\n"
#endif
    "   tmpdir (default=\"/tmp\")\n"
#if S3FS_EXTRAS
    "      - local folder for temporary files.\n"
    "\n"
#endif
#if S3FS_CACHE
    "   S3FS_CACHE (default=\"\" which means disabled)\n"
    "      - local folder to use for local file cache\n"
    "\n"
    "   check_cache_dir_exist (default is disable)\n"
    "      - if S3FS_CACHE is set, check if the cache directory exists.\n"
    "        If this option is not specified, it will be created at runtime\n"
    "        when the cache directory does not exist.\n"
    "\n"
    "   del_cache (delete local file cache)\n"
    "      - delete local file cache when s3fs starts and exits.\n"
    "\n"
#endif
    "   storage_class (default=\"standard\")\n"
#if S3FS_EXTRAS
    "      - store object with specified storage class. Possible values:\n"
    "        standard, standard_ia, onezone_ia, reduced_redundancy,\n"
    "        intelligent_tiering, glacier, glacier_ir, and deep_archive.\n"
    "\n"
#endif
    "   use_rrs (default is disable)\n"
#if S3FS_EXTRAS
    "      - use Amazon's Reduced Redundancy Storage.\n"
    "        this option can not be specified with use_sse.\n"
    "        (can specify use_rrs=1 for old version)\n"
    "        this option has been replaced by new storage_class option.\n"
    "\n"
#endif
    "   use_sse (default is disable)\n"
#if S3FS_EXTRAS
    "      - Specify three type Amazon's Server-Site Encryption: SSE-S3,\n"
    "        SSE-C or SSE-KMS. SSE-S3 uses Amazon S3-managed encryption\n"
    "        keys, SSE-C uses customer-provided encryption keys, and\n"
    "        SSE-KMS uses the master key which you manage in AWS KMS.\n"
    "        You can specify \"use_sse\" or \"use_sse=1\" enables SSE-S3\n"
    "        type (use_sse=1 is old type parameter).\n"
    "        Case of setting SSE-C, you can specify \"use_sse=custom\",\n"
    "        \"use_sse=custom:<custom key file path>\" or\n"
    "        \"use_sse=<custom key file path>\" (only <custom key file path>\n"
    "        specified is old type parameter). You can use \"c\" for\n"
    "        short \"custom\".\n"
    "        The custom key file must be 600 permission. The file can\n"
    "        have some lines, each line is one SSE-C key. The first line\n"
    "        in file is used as Customer-Provided Encryption Keys for\n"
    "        uploading and changing headers etc. If there are some keys\n"
    "        after first line, those are used downloading object which\n"
    "        are encrypted by not first key. So that, you can keep all\n"
    "        SSE-C keys in file, that is SSE-C key history.\n"
    "        If you specify \"custom\" (\"c\") without file path, you\n"
    "        need to set custom key by load_sse_c option or AWSSSECKEYS\n"
    "        environment. (AWSSSECKEYS environment has some SSE-C keys\n"
    "        with \":\" separator.) This option is used to decide the\n"
    "        SSE type. So that if you do not want to encrypt a object\n"
    "        object at uploading, but you need to decrypt encrypted\n"
    "        object at downloading, you can use load_sse_c option instead\n"
    "        of this option.\n"
    "        For setting SSE-KMS, specify \"use_sse=kmsid\" or\n"
    "        \"use_sse=kmsid:<kms id>\". You can use \"k\" for short \"kmsid\".\n"
    "        If you san specify SSE-KMS type with your <kms id> in AWS\n"
    "        KMS, you can set it after \"kmsid:\" (or \"k:\"). If you\n"
    "        specify only \"kmsid\" (\"k\"), you need to set AWSSSEKMSID\n"
    "        environment which value is <kms id>. You must be careful\n"
    "        about that you can not use the KMS id which is not same EC2\n"
    "        region.\n"
    "\n"
#endif
    "   load_sse_c - specify SSE-C keys\n"
#if S3FS_EXTRAS
    "        Specify the custom-provided encryption keys file path for decrypting\n"
    "        at downloading.\n"
    "        If you use the custom-provided encryption key at uploading, you\n"
    "        specify with \"use_sse=custom\". The file has many lines, one line\n"
    "        means one custom key. So that you can keep all SSE-C keys in file,\n"
    "        that is SSE-C key history. AWSSSECKEYS environment is as same as this\n"
    "        file contents.\n"
    "\n"
#endif
    "   public_bucket (default=\"\" which means disabled)\n"
#if S3FS_EXTRAS
    "      - anonymously mount a public bucket when set to 1, ignores the \n"
    "        $HOME/.passwd-s3fs and /etc/passwd-s3fs files.\n"
    "        S3 does not allow copy object api for anonymous users, then\n"
    "        s3fs sets nocopyapi option automatically when public_bucket=1\n"
    "        option is specified.\n"
    "\n"
#endif
    "   passwd_file (default=\"\")\n"
#if S3FS_EXTRAS
    "      - specify which s3fs password file to use\n"
    "\n"
#endif
    "   ahbe_conf (default=\"\" which means disabled)\n"
#if S3FS_EXTRAS
    "      - This option specifies the configuration file path which\n"
    "      file is the additional HTTP header by file (object) extension.\n"
    "      The configuration file format is below:\n"
    "      -----------\n"
    "      line         = [file suffix or regex] HTTP-header [HTTP-values]\n"
    "      file suffix  = file (object) suffix, if this field is empty,\n"
    "                     it means \"reg:(.*)\".(=all object).\n"
    "      regex        = regular expression to match the file (object) path.\n"
    "                     this type starts with \"reg:\" prefix.\n"
    "      HTTP-header  = additional HTTP header name\n"
    "      HTTP-values  = additional HTTP header value\n"
    "      -----------\n"
    "      Sample:\n"
    "      -----------\n"
    "      .gz                    Content-Encoding  gzip\n"
    "      .Z                     Content-Encoding  compress\n"
    "      reg:^/MYDIR/(.*)[.]t2$ Content-Encoding  text2\n"
    "      -----------\n"
    "      A sample configuration file is uploaded in \"test\" directory.\n"
    "      If you specify this option for set \"Content-Encoding\" HTTP \n"
    "      header, please take care for RFC 2616.\n"
    "\n"
#endif
    "   profile (default=\"default\")\n"
#if S3FS_EXTRAS
    "      - Choose a profile from ${HOME}/.aws/credentials to authenticate\n"
    "        against S3. Note that this format matches the AWS CLI format and\n"
    "        differs from the s3fs passwd format.\n"
    "\n"
#endif
    "   connect_timeout (default=\"300\" seconds)\n"
#if S3FS_EXTRAS
    "      - time to wait for connection before giving up\n"
    "\n"
#endif
    "   readwrite_timeout (default=\"120\" seconds)\n"
#if S3FS_EXTRAS
    "      - time to wait between read/write activity before giving up\n"
    "\n"
#endif
    "   list_object_max_keys (default=\"1000\")\n"
#if S3FS_EXTRAS
    "      - specify the maximum number of keys returned by S3 list object\n"
    "        API. The default is 1000. you can set this value to 1000 or more.\n"
    "\n"
#endif
    "   max_stat_cache_size (default=\"100,000\" entries (about 40MB))\n"
#if S3FS_EXTRAS
    "      - maximum number of entries in the stat cache, and this maximum is\n"
    "        also treated as the number of symbolic link cache.\n"
    "\n"
#endif
    "   stat_cache_expire (default is 900))\n"
#if S3FS_EXTRAS
    "      - specify expire time (seconds) for entries in the stat cache.\n"
    "        This expire time indicates the time since stat cached. and this\n"
    "        is also set to the expire time of the symbolic link cache.\n"
    "\n"
#endif
    "   stat_cache_interval_expire (default is 900)\n"
#if S3FS_EXTRAS
    "      - specify expire time (seconds) for entries in the stat cache(and\n"
    "        symbolic link cache).\n"
    "      This expire time is based on the time from the last access time\n"
    "      of the stat cache. This option is exclusive with stat_cache_expire,\n"
    "      and is left for compatibility with older versions.\n"
    "\n"
#endif
    "   disable_noobj_cache (default is enable)\n"
#if S3FS_EXTRAS
    "      - By default s3fs memorizes when an object does not exist up until\n"
    "        the stat cache timeout.  This caching can cause staleness for\n"
    "        applications.  If disabled, s3fs will not memorize objects and may\n"
    "        cause extra HeadObject requests and reduce performance.\n"
    "\n"
#endif
    "   no_check_certificate\n"
#if S3FS_EXTRAS
    "      - server certificate won't be checked against the available \n"
    "      certificate authorities.\n"
    "\n"
#endif
    "   ssl_verify_hostname (default=\"2\")\n"
#if S3FS_EXTRAS
    "      - When 0, do not verify the SSL certificate against the hostname.\n"
    "\n"
#endif
    "   nodnscache (disable DNS cache)\n"
#if S3FS_EXTRAS
    "      - s3fs is always using DNS cache, this option make DNS cache disable.\n"
    "\n"
#endif
    "   nosscache (disable SSL session cache)\n"
#if S3FS_EXTRAS
    "      - s3fs is always using SSL session cache, this option make SSL \n"
    "      session cache disable.\n"
    "\n"
#endif
    "   multireq_max (default=\"20\")\n"
#if S3FS_EXTRAS
    "      - maximum number of parallel request for listing objects.\n"
    "\n"
#endif
    "   parallel_count (default=\"5\")\n"
#if S3FS_EXTRAS
    "      - number of parallel request for uploading big objects.\n"
    "      s3fs uploads large object (over 20MB) by multipart post request, \n"
    "      and sends parallel requests.\n"
    "      This option limits parallel request count which s3fs requests \n"
    "      at once. It is necessary to set this value depending on a CPU \n"
    "      and a network band.\n"
    "\n"
#endif
    "   multipart_size (default=\"10\")\n"
#if S3FS_EXTRAS
    "      - part size, in MB, for each multipart request.\n"
    "      The minimum value is 5 MB and the maximum value is 5 GB.\n"
    "\n"
#endif
    "   multipart_copy_size (default=\"512\")\n"
#if S3FS_EXTRAS
    "      - part size, in MB, for each multipart copy request, used for\n"
    "      renames and mixupload.\n"
    "      The minimum value is 5 MB and the maximum value is 5 GB.\n"
    "      Must be at least 512 MB to copy the maximum 5 TB object size\n"
    "      but lower values may improve performance.\n"
    "\n"
#endif
    "   max_dirty_data (default=\"5120\")\n"
#if S3FS_EXTRAS
    "      - flush dirty data to S3 after a certain number of MB written.\n"
    "      The minimum value is 50 MB. -1 value means disable.\n"
    "      Cannot be used with nomixupload.\n"
    "\n"
#endif
    "   bucket_size (default=maximum long unsigned integer value)\n"
#if S3FS_EXTRAS
    "      - The size of the bucket with which the corresponding\n"
    "      elements of the statvfs structure will be filled. The option\n"
    "      argument is an integer optionally followed by a\n"
    "      multiplicative suffix (GB, GiB, TB, TiB, PB, PiB,\n"
    "      EB, EiB) (no spaces in between). If no suffix is supplied,\n"
    "      bytes are assumed; eg: 20000000, 30GB, 45TiB. Note that\n"
    "      s3fs does not compute the actual volume size (too\n"
    "      expensive): by default it will assume the maximum possible\n"
    "      size; however, since this may confuse other software which\n"
    "      uses s3fs, the advertised bucket size can be set with this\n"
    "      option.\n"
    "\n"
#endif
    "   ensure_diskfree (default 0)\n"
#if S3FS_EXTRAS
    "      - sets MB to ensure disk free space. This option means the\n"
    "        threshold of free space size on disk which is used for the\n"
    "        cache file by s3fs. s3fs makes file for\n"
    "        downloading, uploading and caching files. If the disk free\n"
    "        space is smaller than this value, s3fs do not use disk space\n"
    "        as possible in exchange for the performance.\n"
    "\n"
#endif
    "   multipart_threshold (default=\"25\")\n"
#if S3FS_EXTRAS
    "      - threshold, in MB, to use multipart upload instead of\n"
    "        single-part. Must be at least 5 MB.\n"
    "\n"
#endif
    "   singlepart_copy_limit (default=\"512\")\n"
#if S3FS_EXTRAS
    "      - maximum size, in MB, of a single-part copy before trying \n"
    "      multipart copy.\n"
    "\n"
#endif
    "   host (default=\"https://s3.amazonaws.com\")\n"
#if S3FS_EXTRAS
    "      - Set a non-Amazon host, e.g., https://example.com.\n"
    "\n"
#endif
    "   servicepath (default=\"/\")\n"
#if S3FS_EXTRAS
    "      - Set a service path when the non-Amazon host requires a prefix.\n"
    "\n"
#endif
    "   url (default=\"https://s3.amazonaws.com\")\n"
#if S3FS_EXTRAS
    "      - sets the url to use to access Amazon S3. If you want to use HTTP,\n"
    "        then you can set \"url=http://s3.amazonaws.com\".\n"
    "        If you do not use https, please specify the URL with the url\n"
    "        option.\n"
    "\n"
#endif
    "   endpoint (default=\"us-east-1\")\n"
#if S3FS_EXTRAS
    "      - sets the endpoint to use on signature version 4\n"
    "      If this option is not specified, s3fs uses \"us-east-1\" region as\n"
    "      the default. If the s3fs could not connect to the region specified\n"
    "      by this option, s3fs could not run. But if you do not specify this\n"
    "      option, and if you can not connect with the default region, s3fs\n"
    "      will retry to automatically connect to the other region. So s3fs\n"
    "      can know the correct region name, because s3fs can find it in an\n"
    "      error from the S3 server.\n"
    "\n"
#endif
    "   sigv2 (default is signature version 4 falling back to version 2)\n"
    "      - sets signing AWS requests by using only signature version 2\n"
    "\n"
    "   sigv4 (default is signature version 4 falling back to version 2)\n"
    "      - sets signing AWS requests by using only signature version 4\n"
    "\n"
    "   mp_umask (default is \"0000\")\n"
#if S3FS_EXTRAS
    "      - sets umask for the mount point directory.\n"
    "      If allow_other option is not set, s3fs allows access to the mount\n"
    "      point only to the owner. In the opposite case s3fs allows access\n"
    "      to all users as the default. But if you set the allow_other with\n"
    "      this option, you can control the permissions of the\n"
    "      mount point by this option like umask.\n"
    "\n"
#endif
    "   umask (default is \"0000\")\n"
#if S3FS_EXTRAS
    "      - sets umask for files under the mountpoint. This can allow\n"
    "      users other than the mounting user to read and write to files\n"
    "      that they did not create.\n"
    "\n"
#endif
    "   nomultipart (disable multipart uploads)\n"
#if S3FS_EXTRAS
    "\n"
#endif
    "   streamupload (default is disable)\n"
#if S3FS_EXTRAS
    "      - Enable stream upload.\n"
    "      If this option is enabled, a sequential upload will be performed\n"
    "      in parallel with the write from the part that has been written\n"
    "      during a multipart upload.\n"
    "      This is expected to give better performance than other upload\n"
    "      functions.\n"
    "      Note that this option is still experimental and may change in the\n"
    "      future.\n"
    "\n"
#endif
    "   max_thread_count (default is \"5\")\n"
#if S3FS_EXTRAS
    "      - Specifies the number of threads waiting for stream uploads.\n"
    "      Note that this option and Streamm Upload are still experimental\n"
    "      and subject to change in the future.\n"
    "      This option will be merged with \"parallel_count\" in the future.\n"
    "\n"
#endif
    "   enable_content_md5 (default is disable)\n"
#if S3FS_EXTRAS
    "      - Allow S3 server to check data integrity of uploads via the\n"
    "      Content-MD5 header. This can add CPU overhead to transfers.\n"
    "\n"
#endif
    "   enable_unsigned_payload (default is disable)\n"
#if S3FS_EXTRAS
    "      - Do not calculate Content-SHA256 for PutObject and UploadPart\n"
    "      payloads. This can reduce CPU overhead to transfers.\n"
    "\n"
#endif
    "   ecs (default is disable)\n"
#if S3FS_EXTRAS
    "      - This option instructs s3fs to query the ECS container credential\n"
    "      metadata address instead of the instance metadata address.\n"
    "\n"
#endif
    "   iam_role (default is no IAM role)\n"
#if S3FS_EXTRAS
    "      - This option requires the IAM role name or \"auto\". If you specify\n"
    "      \"auto\", s3fs will automatically use the IAM role names that are set\n"
    "      to an instance. If you specify this option without any argument, it\n"
    "      is the same as that you have specified the \"auto\".\n"
    "\n"
#endif
    "   imdsv1only (default is to use IMDSv2 with fallback to v1)\n"
#if S3FS_EXTRAS
    "      - AWS instance metadata service, used with IAM role authentication,\n"
    "      supports the use of an API token. If you're using an IAM role\n"
    "      in an environment that does not support IMDSv2, setting this flag\n"
    "      will skip retrieval and usage of the API token when retrieving\n"
    "      IAM credentials.\n"
    "\n"
#endif
    "   ibm_iam_auth (default is not using IBM IAM authentication)\n"
#if S3FS_EXTRAS
    "      - This option instructs s3fs to use IBM IAM authentication.\n"
    "      In this mode, the AWSAccessKey and AWSSecretKey will be used as\n"
    "      IBM's Service-Instance-ID and APIKey, respectively.\n"
    "\n"
#endif
    "   ibm_iam_endpoint (default is https://iam.cloud.ibm.com)\n"
#if S3FS_EXTRAS
    "      - sets the URL to use for IBM IAM authentication.\n"
    "\n"
#endif
    "   credlib (default=\"\" which means disabled)\n"
#if S3FS_EXTRAS
    "      - Specifies the shared library that handles the credentials\n"
    "      containing the authentication token.\n"
    "      If this option is specified, the specified credential and token\n"
    "      processing provided by the shared library ant will be performed\n"
    "      instead of the built-in credential processing.\n"
    "      This option cannot be specified with passwd_file, profile,\n"
    "      use_session_token, ecs, ibm_iam_auth, ibm_iam_endpoint, imdsv1only\n"
    "      and iam_role option.\n"
    "\n"
#endif
    "   credlib_opts (default=\"\" which means disabled)\n"
#if S3FS_EXTRAS
    "      - Specifies the options to pass when the shared library specified\n"
    "      in credlib is loaded and then initialized.\n"
    "      For the string specified in this option, specify the string defined\n"
    "      by the shared library.\n"
    "\n"
#endif
    "   use_xattr (default is not handling the extended attribute)\n"
#if S3FS_EXTRAS
    "      Enable to handle the extended attribute (xattrs).\n"
    "      If you set this option, you can use the extended attribute.\n"
    "      For example, encfs and ecryptfs need to support the extended attribute.\n"
    "      Notice: if s3fs handles the extended attribute, s3fs can not work to\n"
    "      copy command with preserve=mode.\n"
    "\n"
#endif
    "   noxmlns (disable registering xml name space)\n"
#if S3FS_EXTRAS
    "        disable registering xml name space for response of \n"
    "        ListBucketResult and ListVersionsResult etc. Default name \n"
    "        space is looked up from \"http://s3.amazonaws.com/doc/2006-03-01\".\n"
    "        This option should not be specified now, because s3fs looks up\n"
    "        xmlns automatically after v1.66.\n"
    "\n"
#endif
    "   nomixupload (disable copy in multipart uploads)\n"
#if S3FS_EXTRAS
    "        Disable to use PUT (copy api) when multipart uploading large size objects.\n"
    "        By default, when doing multipart upload, the range of unchanged data\n"
    "        will use PUT (copy api) whenever possible.\n"
    "        When nocopyapi or norenameapi is specified, use of PUT (copy api) is\n"
    "        invalidated even if this option is not specified.\n"
    "\n"
#endif
    "   nocopyapi (for other incomplete compatibility object storage)\n"
#if S3FS_EXTRAS
    "        Enable compatibility with S3-like APIs which do not support\n"
    "        PUT (copy api).\n"
    "        If you set this option, s3fs do not use PUT with \n"
    "        \"x-amz-copy-source\" (copy api). Because traffic is increased\n"
    "        2-3 times by this option, we do not recommend this.\n"
    "\n"
#endif
    "   norenameapi (for other incomplete compatibility object storage)\n"
#if S3FS_EXTRAS
    "        Enable compatibility with S3-like APIs which do not support\n"
    "        PUT (copy api).\n"
    "        This option is a subset of nocopyapi option. The nocopyapi\n"
    "        option does not use copy-api for all command (ex. chmod, chown,\n"
    "        touch, mv, etc), but this option does not use copy-api for\n"
    "        only rename command (ex. mv). If this option is specified with\n"
    "        nocopyapi, then s3fs ignores it.\n"
    "\n"
#endif
    "   use_path_request_style (use legacy API calling style)\n"
#if S3FS_EXTRAS
    "        Enable compatibility with S3-like APIs which do not support\n"
    "        the virtual-host request style, by using the older path request\n"
    "        style.\n"
    "\n"
#endif
    "   listobjectsv2 (use ListObjectsV2)\n"
#if S3FS_EXTRAS
    "        Issue ListObjectsV2 instead of ListObjects, useful on object\n"
    "        stores without ListObjects support.\n"
    "\n"
#endif
    "   noua (suppress User-Agent header)\n"
#if S3FS_EXTRAS
    "        Usually s3fs outputs of the User-Agent in \"s3fs/<version> (commit\n"
    "        hash <hash>; <using ssl library name>)\" format.\n"
    "        If this option is specified, s3fs suppresses the output of the\n"
    "        User-Agent.\n"
    "\n"
#endif
    "   cipher_suites\n"
#if S3FS_EXTRAS
    "        Customize the list of TLS cipher suites.\n"
    "        Expects a colon separated list of cipher suite names.\n"
    "        A list of available cipher suites, depending on your TLS engine,\n"
    "        can be found on the CURL library documentation:\n"
    "        https://curl.haxx.se/docs/ssl-ciphers.html\n"
    "\n"
#endif
    "   instance_name - The instance name of the current s3fs mountpoint.\n"
#if S3FS_EXTRAS
    "        This name will be added to logging messages and user agent headers sent by s3fs.\n"
    "\n"
#endif
    "   complement_stat (complement lack of file/directory mode)\n"
#if S3FS_EXTRAS
    "        s3fs complements lack of information about file/directory mode\n"
    "        if a file or a directory object does not have x-amz-meta-mode\n"
    "        header. As default, s3fs does not complements stat information\n"
    "        for a object, then the object will not be able to be allowed to\n"
    "        list/modify.\n"
    "\n"
#endif
    "   compat_dir (enable support of alternative directory names)\n"
#if S3FS_EXTRAS
    "        s3fs supports two different naming schemas \"dir/\" and\n"
    "        \"dir\" to map directory names to S3 objects and\n"
    "        vice versa by default. As a third variant, directories can be\n"
    "        determined indirectly if there is a file object with a path (e.g.\n"
    "        \"/dir/file\") but without the parent directory.\n"
    "        This option enables a fourth variant, \"dir_$folder$\", created by\n"
    "        older applications.\n"
    "        \n"
    "        S3fs uses only the first schema \"dir/\" to create S3 objects for\n"
    "        directories."
    "        \n"
    "        The support for these different naming schemas causes an increased\n"
    "        communication effort.\n"
    "\n"
#endif
    "   use_wtf8 - support arbitrary file system encoding.\n"
#if S3FS_EXTRAS
    "        S3 requires all object names to be valid UTF-8. But some\n"
    "        clients, notably Windows NFS clients, use their own encoding.\n"
    "        This option re-encodes invalid UTF-8 object names into valid\n"
    "        UTF-8 by mapping offending codes into a 'private' codepage of the\n"
    "        Unicode set.\n"
    "        Useful on clients not using UTF-8 as their file system encoding.\n"
    "\n"
#endif
    "   use_session_token - indicate that session token should be provided.\n"
#if S3FS_EXTRAS
    "        If credentials are provided by environment variables this switch\n"
    "        forces presence check of AWSSESSIONTOKEN variable.\n"
    "        Otherwise an error is returned.\n"
    "\n"
#endif
    "   requester_pays (default is disable)\n"
#if S3FS_EXTRAS
    "        This option instructs s3fs to enable requests involving\n"
    "        Requester Pays buckets.\n"
    "        It includes the 'x-amz-request-payer=requester' entry in the\n"
    "        request header.\n"
    "\n"
#endif
    "   mime (default is \"/etc/mime.types\")\n"
#if S3FS_EXTRAS
    "        Specify the path of the mime.types file.\n"
    "        If this option is not specified, the existence of \"/etc/mime.types\"\n"
    "        is checked, and that file is loaded as mime information.\n"
    "        If this file does not exist on macOS, then \"/etc/apache2/mime.types\"\n"
    "        is checked as well.\n"
    "\n"
#endif
    "   proxy (default=\"\")\n"
#if S3FS_EXTRAS
    "        This option specifies a proxy to S3 server.\n"
    "        Specify the proxy with '[<scheme://]hostname(fqdn)[:<port>]' formatted.\n"
    "        '<schema>://' can be omitted, and 'http://' is used when omitted.\n"
    "        Also, ':<port>' can also be omitted. If omitted, port 443 is used for\n"
    "        HTTPS schema, and port 1080 is used otherwise.\n"
    "        This option is the same as the curl command's '--proxy(-x)' option and\n"
    "        libcurl's 'CURLOPT_PROXY' flag.\n"
    "        This option is equivalent to and takes precedence over the environment\n"
    "        variables 'http_proxy', 'all_proxy', etc.\n"
    "\n"
#endif
    "   proxy_cred_file (default=\"\")\n"
#if S3FS_EXTRAS
    "        This option specifies the file that describes the username and\n"
    "        passphrase for authentication of the proxy when the HTTP schema\n"
    "        proxy is specified by the 'proxy' option.\n"
    "        Username and passphrase are valid only for HTTP schema. If the HTTP\n"
    "        proxy does not require authentication, this option is not required.\n"
    "        Separate the username and passphrase with a ':' character and\n"
    "        specify each as a URL-encoded string.\n"
    "\n"
#endif
    "   logfile - specify the log output file.\n"
#if S3FS_EXTRAS
    "        s3fs outputs the log file to syslog. Alternatively, if s3fs is\n"
    "        started with the \"-f\" option specified, the log will be output\n"
    "        to the stdout/stderr.\n"
    "        You can use this option to specify the log file that s3fs outputs.\n"
    "        If you specify a log file with this option, it will reopen the log\n"
    "        file when s3fs receives a SIGHUP signal. You can use the SIGHUP\n"
    "        signal for log rotation.\n"
    "\n"
#endif
    "   dbglevel (default=\"crit\")\n"
#if S3FS_EXTRAS
    "        Set the debug message level. set value as crit (critical), err\n"
    "        (error), warn (warning), info (information) to debug level.\n"
    "        default debug level is critical. If s3fs run with \"-d\" option,\n"
    "        the debug level is set information. When s3fs catch the signal\n"
    "        SIGUSR2, the debug level is bump up.\n"
    "\n"
#endif
    "   curldbg - put curl debug message\n"
#if S3FS_EXTRAS
    "        Put the debug message from libcurl when this option is specified.\n"
    "        Specify \"normal\" or \"body\" for the parameter.\n"
    "        If the parameter is omitted, it is the same as \"normal\".\n"
    "        If \"body\" is specified, some API communication body data will be\n"
    "        output in addition to the debug message output as \"normal\".\n"
    "\n"
#endif
    "   no_time_stamp_msg - no time stamp in debug message\n"
#if S3FS_EXTRAS
    "        The time stamp is output to the debug message by default.\n"
    "        If this option is specified, the time stamp will not be output\n"
    "        in the debug message.\n"
    "        It is the same even if the environment variable \"S3FS_MSGTIMESTAMP\"\n"
    "        is set to \"no\".\n"
    "\n"
#endif
    "   set_check_cache_sigusr1 (default is stdout)\n"
#if S3FS_EXTRAS
    "        If the cache is enabled, you can check the integrity of the\n"
    "        cache file and the cache file's stats info file.\n"
    "        This option is specified and when sending the SIGUSR1 signal\n"
    "        to the s3fs process checks the cache status at that time.\n"
    "        This option can take a file path as parameter to output the\n"
    "        check result to that file. The file path parameter can be omitted.\n"
    "        If omitted, the result will be output to stdout or syslog.\n"
    "\n"
#endif
    "   update_parent_dir_stat (default is disable)\n"
#if S3FS_EXTRAS
    "        The parent directory's mtime and ctime are updated when a file or\n"
    "        directory is created or deleted (when the parent directory's inode is\n"
    "        updated).\n"
    "        By default, parent directory statistics are not updated.\n"
    "\n"
    "FUSE/mount Options:\n"
    "\n"
    "   Most of the generic mount options described in 'man mount' are\n"
    "   supported (ro, rw, suid, nosuid, dev, nodev, exec, noexec, atime,\n"
    "   noatime, sync async, dirsync). Filesystems are mounted with\n"
    "   '-onodev,nosuid' by default, which can only be overridden by a\n"
    "   privileged user.\n"
    "   \n"
    "   There are many FUSE specific mount options that can be specified.\n"
    "   e.g. allow_other  See the FUSE's README for the full set.\n"
    "\n"
#endif
    "Utility mode Options:\n"
    "\n"
    " -u, --incomplete-mpu-list\n"
    "        Lists multipart incomplete objects uploaded to the specified\n"
    "        bucket.\n"
    " --incomplete-mpu-abort (=all or =<date format>)\n"
    "        Delete the multipart incomplete object uploaded to the specified\n"
    "        bucket.\n"
    "        If \"all\" is specified for this option, all multipart incomplete\n"
    "        objects will be deleted. If you specify no argument as an option,\n"
    "        objects older than 24 hours (24H) will be deleted (This is the\n"
    "        default value). You can specify an optional date format. It can\n"
    "        be specified as year, month, day, hour, minute, second, and it is\n"
    "        expressed as \"Y\", \"M\", \"D\", \"h\", \"m\", \"s\" respectively.\n"
    "        For example, \"1Y6M10D12h30m30s\".\n"
    "\n"
    "Miscellaneous Options:\n"
    "\n"
    " -h, --help        Output this help.\n"
    "     --version     Output version info.\n"
    " -d  --debug       Turn on DEBUG messages to syslog. Specifying -d\n"
    "                   twice turns on FUSE debug messages to STDOUT.\n"
    " -f                FUSE foreground option - do not run as daemon.\n"
    " -s                FUSE single-threaded option\n"
    "                   disable multi-threaded operation\n"
    "\n"
    "\n"
    "s3fs home page: <https://github.com/s3fs-fuse/s3fs-fuse>\n"
    ;

//-------------------------------------------------------------------
// Functions
//-------------------------------------------------------------------
void show_usage()
{
    printf("Usage: %s BUCKET:[PATH] MOUNTPOINT [OPTION]...\n", program_name.c_str());
}

void show_help()
{
    show_usage();
    printf(help_string);
}

void show_version()
{
    printf(
    "Amazon Simple Storage Service File System V%s (commit:%s) with %s\n"
    "Copyright (C) 2010 Randy Rizun <rrizun@gmail.com>\n"
    "License GPL2: GNU GPL version 2 <https://gnu.org/licenses/gpl.html>\n"
    "This is free software: you are free to change and redistribute it.\n"
    "There is NO WARRANTY, to the extent permitted by law.\n",
    VERSION, COMMIT_HASH_VAL, s3fs_crypt_lib_name());
}

const char* short_version()
{
    static const char short_ver[] = "s3fs version " VERSION "(" COMMIT_HASH_VAL ")";
    return short_ver;
}

/*
* Local variables:
* tab-width: 4
* c-basic-offset: 4
* End:
* vim600: expandtab sw=4 ts=4 fdm=marker
* vim<600: expandtab sw=4 ts=4
*/
