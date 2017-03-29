#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import json
import traceback
import hashlib

# https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
import lz4framed


logger = logging.getLogger(__name__)


class Lz4Processor(object):
    """
    Very simple processor of the newline separated structured data, compressed by LZ4
    """
    def __init__(self, is_json=True, *args, **kwargs):
        self.is_json = is_json

        # State of the processing
        self.digest = None
        self.digest_final_hex = None

        self.total_len = 0
        self.ctr = 0
        self.chunk_idx = 0
        self.buffer = ''

        # Control / callbacks
        self.abort = False
        self.on_chunk_process = None
        self.on_record_process = None

    def process(self, file_like):
        """
        Processes file like object in a streamed manner.
        :param file_like: 
        :return: 
        """
        self.total_len = 0
        self.digest = hashlib.sha256()

        for idx, chunk in enumerate(lz4framed.Decompressor(file_like)):
            self.chunk_idx = idx
            self.process_chunk(self.chunk_idx, chunk)

            self.total_len += len(chunk)
            self.digest.update(chunk)

            if self.abort:
                logger.info('Abort set, terminating')
                return

        # Finish the buffer completely
        self.chunk_idx += 1
        self.process_chunk(self.chunk_idx, '', True)

        self.digest_final_hex = self.digest.hexdigest()
        logger.info('Processing finished, total length: %s, hash: %s' % (self.total_len, self.digest_final_hex))

    def process_chunk(self, idx, chunk, finalize=False):
        """
        Process one chunk of decrypted data. Length is arbitrary. We have to watch out the underlying format.
        :param idx: chunk index
        :param chunk: data chunk to process
        :param finalize: if true no more data is going to be loaded, read all what you can 
        :return: 
        """
        self.buffer += chunk

        if self.on_chunk_process is not None:
            self.on_chunk_process(idx, chunk)

        while True:
            pos = self.buffer.find('\n')
            if pos < 0:
                # Check the size of the buffer, log if buffer is too long. Can signalize something broke
                ln = len(self.buffer)
                if ln > 100000:
                    logger.info('Chunk %d without newline, len: %d' % (idx, ln))

                # Wait for next chunk
                if not finalize:
                    return
                else:
                    pos = ln

            part = (self.buffer[0:pos]).strip()
            self.buffer = (self.buffer[pos+1:]).strip()
            self.process_record_wrapper(idx, part)

    def process_record_wrapper(self, idx, part):
        """
        Process record - safe wrapper
        :param js: 
        :return: 
        """
        self.ctr += 1
        try:
            obj = json.loads(part) if self.is_json else part
            self.process_record(idx, obj)

        except Exception as e:
            logger.error('Exception when parsing pos %d, part: %s' % (self.ctr, e))
            logger.info(traceback.format_exc())

    def process_record(self, idx, record):
        """
        Processing of the record - up to you...
        :param idx: 
        :param record: 
        :return: 
        """
        if self.on_record_process is not None:
            self.on_record_process(idx, record)




