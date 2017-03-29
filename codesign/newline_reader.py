#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import json
import traceback
import hashlib


logger = logging.getLogger(__name__)


class NewlineReader(object):
    """
    Very simple newline separated JSON reader.
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

        for idx, chunk in enumerate(file_like):
            logger.info('chunk: %d' % idx)

            self.chunk_idx = idx
            for x in self.process_chunk(self.chunk_idx, chunk):
                yield x

            self.total_len += len(chunk)
            self.digest.update(chunk)

            if self.abort:
                logger.info('Abort set, terminating')
                return

        # Finish the buffer completely
        self.chunk_idx += 1
        for x in self.process_chunk(self.chunk_idx, '', True):
            yield x

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

            self.ctr += 1
            try:
                obj = json.loads(part) if self.is_json else part
                yield idx, obj

            except Exception as e:
                logger.error('Exception when parsing pos %d, part: %s' % (self.ctr, e))
                logger.info(traceback.format_exc())
                logger.info(part)





