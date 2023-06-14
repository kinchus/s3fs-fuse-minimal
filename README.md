# s3fs

s3fs allows Linux, macOS, and FreeBSD to mount an S3 bucket via [FUSE(Filesystem in Userspace)](https://github.com/libfuse/libfuse).  
s3fs makes you operate files and directories in S3 bucket like a local file system.  
s3fs preserves the native object format for files, allowing use of other tools like [AWS CLI](https://github.com/aws/aws-cli).  

[![s3fs-fuse CI](https://github.com/s3fs-fuse/s3fs-fuse/workflows/s3fs-fuse%20CI/badge.svg)](https://github.com/s3fs-fuse/s3fs-fuse/actions)
[![Twitter Follow](https://img.shields.io/twitter/follow/s3fsfuse.svg?style=social&label=Follow)](https://twitter.com/s3fsfuse)

# s3fs-minimal

Porting of the original s3fs fuse project targeting embedded OSes like OpenWrt.
