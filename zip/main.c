
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <zlib.h>

/*
 * https://www.pkware.com/documents/casestudies/APPNOTE.TXT
 * http://codeandlife.com/2014/01/01/unzip-library-for-c/
 */

/*
   4.3.16  End of central directory record:

      end of central dir signature                                                  4 bytes  (0x06054b50)
      number of this disk		                                            2 bytes
      number of the disk with the start of the central directory                    2 bytes
      total number of entries in the central directory on this disk                 2 bytes
      total number of entries in the central directory                              2 bytes
      size of the central directory                                                 4 bytes
      offset of start of central directory with respect to the starting disk number 4 bytes
      .ZIP file comment length                                                      2 bytes
      .ZIP file comment                                                     (variable size)
 */

#define Z_RECORD_SIGNATURE 0x06054b50
#define Z_FILE_SIGNATURE   0x04034b50

struct __attribute__ ((__packed__)) z_record {
    uint32_t signature;
    uint16_t diskNumber; // unsupported
    uint16_t centralDirectoryDiskNumber; // unsupported
    uint16_t numEntriesThisDisk; // unsupported
    uint16_t numEntries;
    uint32_t centralDirectorySize;
    uint32_t centralDirectoryOffset;
    uint16_t zipCommentLength;
    // Followed by .ZIP file comment (variable size)
};


/* 
   4.3.12  Central directory structure:

      [central directory header 1]
      .
      .
      . 
      [central directory header n]
      [digital signature] 

      File header:

        central file header signature   4 bytes  (0x02014b50)
        version made by                 2 bytes
        version needed to extract       2 bytes
        general purpose bit flag        2 bytes
        compression method              2 bytes
        last mod file time              2 bytes
        last mod file date              2 bytes
        crc-32                          4 bytes
        compressed size                 4 bytes
        uncompressed size               4 bytes
        file name length                2 bytes
        extra field length              2 bytes
        file comment length             2 bytes
        disk number start               2 bytes
        internal file attributes        2 bytes
        external file attributes        4 bytes
        relative offset of local header 4 bytes

        file name (variable size)
        extra field (variable size)
        file comment (variable size)
 */

struct __attribute__ ((__packed__)) z_central_directory_header {
    uint32_t signature;
    uint16_t versionMadeBy;          // unsupported
    uint16_t versionNeededToExtract; // unsupported
    uint16_t generalPurposeBitFlag;  // unsupported
    uint16_t compressionMethod;
    uint16_t lastModFileTime;
    uint16_t lastModFileDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t fileNameLength;
    uint16_t extraFieldLength;       // unsupported
    uint16_t fileCommentLength;      // unsupported
    uint16_t diskNumberStart;        // unsupported
    uint16_t internalFileAttributes; // unsupported
    uint32_t externalFileAttributes; // unsupported
    uint32_t relativeOffsetOflocalHeader;
};

/*
   4.3.7  Local file header:

      local file header signature     4 bytes  (0x04034b50)
      version needed to extract       2 bytes
      general purpose bit flag        2 bytes
      compression method              2 bytes
      last mod file time              2 bytes
      last mod file date              2 bytes
      crc-32                          4 bytes
      compressed size                 4 bytes
      uncompressed size               4 bytes
      file name length                2 bytes
      extra field length              2 bytes

      file name (variable size)
      extra field (variable size)
 */

struct __attribute__((packed)) z_local_file_header {
    uint32_t signature;
    uint16_t versionNeededToExtract; // unsupported
    uint16_t generalPurposeBitFlag; // unsupported
    uint16_t compressionMethod;
    uint16_t lastModFileTime;
    uint16_t lastModFileDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t fileNameLength;
    uint16_t extraFieldLength; // unsupported
};

struct z_file_header {
    char * filename;
    uint32_t offset;
};

struct z_data_header {
    off_t offset;
    int method;
    uint32_t crc32;
    size_t compressed_size;
    size_t uncompressed_size;
};

void z_free_central_directory(struct z_file_header * file_hdr, const int count)
{
    if (file_hdr != NULL) {
        int i;

        for (i = 0 ; i < count ; i++) {
            if (file_hdr[i].filename == NULL)
                break;
            free(file_hdr[i].filename);
        }
        free(file_hdr);
    }
}

int z_get_local_file_header(int fd, const struct z_file_header * file_hdr, struct z_data_header * data_hdr)
{
    struct z_local_file_header hdr;
    ssize_t s;

    if (lseek(fd, file_hdr->offset, SEEK_SET) == (off_t)(-1)) {
        fprintf(stderr, "Failed to seek to <%s> local header : %s\n", file_hdr->filename, strerror(errno));
        goto err;
    }

    s = read(fd, &hdr, sizeof hdr);
    if (s < 0) {
        fprintf(stderr, "Failed to read <%s> local header : %s\n", file_hdr->filename, strerror(errno));
        goto err;
    }

    if ((size_t)s != sizeof hdr) {
        fprintf(stderr, "No local header for <%s> found\n", file_hdr->filename);
        goto err;
    }

    if (hdr.signature != Z_FILE_SIGNATURE) {
        fprintf(stderr, "Invalid local header for <%s> found\n", file_hdr->filename);
        goto err;
    }

    if ((hdr.fileNameLength + hdr.extraFieldLength) != 0) {
        if (lseek(fd, hdr.fileNameLength + hdr.extraFieldLength, SEEK_CUR) == (off_t)(-1)) {
            fprintf(stderr, "No data found for <%s>\n", file_hdr->filename);
            goto err;
        }
    }

    data_hdr->offset = lseek(fd, 0, SEEK_CUR);
    if (data_hdr->offset == (off_t)(-1)) {
        fprintf(stderr, "Failed to get data offset for <%s> : %s\n", file_hdr->filename, strerror(errno));
        goto err;
    }
    data_hdr->method = (int )hdr.compressionMethod;
    data_hdr->crc32 = hdr.crc32;
    data_hdr->compressed_size = (size_t)hdr.compressedSize;
    data_hdr->uncompressed_size = (size_t)hdr.uncompressedSize;
    return 0;

err:
    return -1;
}

int z_get_central_directory(int fd, const struct z_record * record, struct z_file_header **res)
{
    uint16_t i;
    struct z_file_header * file_hdr;

    if (lseek(fd, record->centralDirectoryOffset, SEEK_SET) == (off_t)(-1)) {
        fprintf(stderr, "Failed to seek to cental directory : %s\n", strerror(errno));
        goto err;
    }

    file_hdr = calloc(record->numEntries, sizeof file_hdr[0]);
    if (file_hdr == NULL) {
        fprintf(stderr, "Failed to allocate cental file_hdrionary : %s\n", strerror(errno));
        goto err;
    }

    for (i = 0 ; i < record->numEntries ; i ++) {
        struct z_central_directory_header hdr;
        ssize_t s;

        s = read(fd, &hdr, sizeof hdr);
        if (s < 0) {
            fprintf(stderr, "Failed to read directory header : %s\n", strerror(errno));
            goto free_err;
        }

        if ((size_t)s != sizeof hdr) {
            fprintf(stderr, "No directory header found\n");
            goto free_err;
        }

        if (hdr.signature != 0x02014B50) {
            fprintf(stderr, "Invalid directory header found\n");
            goto free_err;
        }

        file_hdr[i].filename = calloc(1, hdr.fileNameLength + 1);
        if (file_hdr[i].filename == NULL) {
            fprintf(stderr, "Failed to allocate directory header filename : %s\n", strerror(errno));
            goto free_err;
        }

        file_hdr[i].offset = hdr.relativeOffsetOflocalHeader;
        s = read(fd, file_hdr[i].filename, hdr.fileNameLength);
        if (s < 0) {
            fprintf(stderr, "Failed to read directory header filename : %s\n", strerror(errno));
            goto free_err;
        }

        if ((hdr.extraFieldLength + hdr.fileCommentLength) != 0) {
            if (lseek(fd, hdr.extraFieldLength + hdr.fileCommentLength, SEEK_CUR) == (off_t) -1) {
                fprintf(stderr, "Failed to seek to next header : %s\n", strerror(errno));
                goto free_err;
            }
        }
    }

    *res = file_hdr;
    return (int )record->numEntries;

free_err:
    z_free_central_directory(file_hdr, record->numEntries);
err:
    *res = NULL;
    return -1;
}

int z_get_record(int fd, struct z_record * end)
{
    const size_t end_size = sizeof end[0];

    if (lseek(fd, -(ssize_t)end_size, SEEK_END) == (off_t) -1) {
        fprintf(stderr, "Failed to seek to the end : %s\n", strerror(errno));
        goto err;
    }

    for (;;) {
        ssize_t s;
        off_t off;

        off = lseek(fd, 0, SEEK_CUR);
        s = read(fd, end, end_size);
        if (s < 0) {
            fprintf(stderr, "Failed to read end of record : %s\n", strerror(errno));
            goto err;
        }

        if ((size_t)s != end_size) {
            fprintf(stderr, "No end of record found\n");
            goto err;
        }

        if (end->signature == Z_RECORD_SIGNATURE) {
            fprintf(stderr, "End record found at <%ld>\n", off);
            break;
        }

        if (lseek(fd, -((ssize_t)end_size) - 1, SEEK_CUR) == (off_t ) -1) {
            fprintf(stderr, "Failed to seek to end of record : %s\n", strerror(errno));
            goto err;
        }
    }

    return 0;

err:
    return -1;
}

int z_decompress(int fd_input, const off_t offset, const size_t input_size, const char * filename)
{
    int fd_output;
    size_t input_done;
    char in_buff[4 * 1024];
    char out_buff[4 * 1024];
    z_stream strm;
    const size_t max_input = (input_size < sizeof in_buff) ? input_size : sizeof in_buff;
    int ret;

    if (lseek(fd_input, offset, SEEK_SET) == (off_t)-1) {
        fprintf(stderr, "Failed to seek to data: %s\n", strerror(errno));
        goto err;
    }

    fd_output = open(filename, O_WRONLY | O_CREAT, 0644);
    if (fd_output < 0) {
        fprintf(stderr, "Failed to open <%s> : %s\n", filename, strerror(errno));
        goto err;
    }

    strm.next_in = Z_NULL;
    strm.avail_in = 0;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    /* Use inflateInit2 with negative window bits to indicate raw data */
    ret = inflateInit2(&strm, -MAX_WBITS);
    if (ret != Z_OK) {
        fprintf(stderr, "inflateInit failed : errcode = <%d>\n", ret);
        goto close_err;
    }

    strm.next_in = Z_NULL;
    strm.avail_in = 0;
    strm.next_out = Z_NULL;
    strm.avail_out = 0;

    input_done = 0;
    do {
        ssize_t s;

        if (input_done >= input_size) {
            fprintf(stderr, "Compressed data stream end expected\n");
            goto free_err;
        }

        s = read(fd_input, in_buff, max_input);
        if (s < 0) {
            fprintf(stderr, "Failed to read compressed data : %s\n", strerror(errno));
            goto free_err;
        }

        if (s == 0) {
            fprintf(stderr, "Unexpected EOF in compressed data : %s\n", strerror(errno));
            goto free_err;
        }
        input_done += s;

        strm.next_in = (void *)in_buff;
        strm.avail_in = s;

        do {
            size_t out_data;
            size_t done;

            strm.avail_out = sizeof out_buff;
            strm.next_out = (void *)out_buff;

            ret = inflate(&strm, Z_NO_FLUSH);
            switch (ret) {
            case Z_STREAM_ERROR:
            case Z_NEED_DICT:
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                fprintf(stderr, "Failed to inflate data : errcode = <%d>\n", ret);
                goto free_err;
            }

            out_data = sizeof out_buff - strm.avail_out;

            done = 0;
            while (done < out_data) {
                s = write(fd_output, out_buff + done, out_data - done);
                if (s < 0) {
                    fprintf(stderr, "Failed to write uncompressed data : %s\n", strerror(errno));
                    goto free_err;
                }
                done += s;
            }
        } while (strm.avail_out == 0);
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    close(fd_output);
    return 0;

free_err:
    inflateEnd(&strm);
close_err:
    close(fd_output);
err:
    return -1;
}

int main(int ac, char **av)
{
    int fd;
    char * filename;
    struct z_record end;
    struct z_file_header * file_hdr;
    int file_hdr_count;
    int i;

    if (ac < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", av[0]);
        goto err;
    }
    filename = av[1];

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open <%s> : %s\n", filename, strerror(errno));
        goto err;
    }

    if (z_get_record(fd, &end) < 0)
        goto close_err;

    file_hdr_count = z_get_central_directory(fd, &end, &file_hdr);
    if (file_hdr_count < 0)
        goto close_err;

    for (i = 0 ; i < file_hdr_count ; i++) {
        struct z_data_header data_hdr;

        if (strcmp("AndroidManifest.xml", file_hdr[i].filename) != 0)
            continue;

        z_get_local_file_header(fd, &file_hdr[i], &data_hdr);
        printf("<%s> : %ld, compressed = <%zd>, uncompressed = <%zd>, method = <%d>\n", file_hdr[i].filename, data_hdr.offset, data_hdr.compressed_size, data_hdr.uncompressed_size, data_hdr.method);

        z_decompress(fd, data_hdr.offset, data_hdr.compressed_size, file_hdr[i].filename);
    }

    z_free_central_directory(file_hdr, file_hdr_count);

    close(fd);
    return 0;

close_err:
    close(fd);
err:
    return 1;
}
