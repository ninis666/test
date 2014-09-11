
int jzReadData(FILE * zip, JZFileHeader * header, void *buffer)
{
    unsigned char *bytes = (unsigned char *)buffer;     // cast
    long compressedLeft, uncompressedLeft;
    z_stream strm;
    int ret;

    if (header->compressionMethod == 0) {       // Store - just read it
        if (fread(buffer, 1, header->uncompressedSize, zip) < header->uncompressedSize || ferror(zip))
            return Z_ERRNO;
    } else if (header->compressionMethod == 8) {        // Deflate - using zlib
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;

        strm.avail_in = 0;
        strm.next_in = Z_NULL;

        // Use inflateInit2 with negative window bits to indicate raw data
        if ((ret = inflateInit2(&strm, -MAX_WBITS)) != Z_OK)
            return ret;         // Zlib errors are negative

        // Inflate compressed data
        for (compressedLeft = header->compressedSize, uncompressedLeft = header->uncompressedSize; compressedLeft && uncompressedLeft && ret != Z_STREAM_END; compressedLeft -= strm.avail_in) {
            // Read next chunk
            strm.avail_in = fread(jzBuffer, 1, (sizeof(jzBuffer) < compressedLeft) ? sizeof(jzBuffer) : compressedLeft, zip);

            if (strm.avail_in == 0 || ferror(zip)) {
                inflateEnd(&strm);
                return Z_ERRNO;
            }

            strm.next_in = jzBuffer;
            strm.avail_out = uncompressedLeft;
            strm.next_out = bytes;

            compressedLeft -= strm.avail_in;    // inflate will change avail_in

            ret = inflate(&strm, Z_NO_FLUSH);

            if (ret == Z_STREAM_ERROR)
                return ret;     // shouldn't happen

            switch (ret) {
                case Z_NEED_DICT:
                    ret = Z_DATA_ERROR; /* and fall through */
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    (void)inflateEnd(&strm);
                    return ret;
            }

            bytes += uncompressedLeft - strm.avail_out; // bytes uncompressed
            uncompressedLeft = strm.avail_out;
        }

        inflateEnd(&strm);
    } else {
        return Z_ERRNO;
    }

    return Z_OK;
}
