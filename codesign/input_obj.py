#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Input objects taken from polynomial verifiers
"""


import hashlib
import logging
import os
import requests
import traceback
import threading
import time
import collections


logger = logging.getLogger(__name__)


class InputObject(object):
    """
    Input stream object.
    Can be a file, stream, or something else
    """
    def __init__(self, *args, **kwargs):
        self.sha256 = hashlib.sha256()
        self.data_read = 0

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __repr__(self):
        return 'InputObject()'

    def check(self):
        """
        Checks if stream is readable
        :return:
        """

    def size(self):
        """
        Returns the size of the data
        :return:
        """
        return -1

    def read(self, size=None):
        """
        Reads size of data
        :param size:
        :return:
        """
        raise NotImplementedError('Not implemented - base class')

    def handle(self):
        """
        Returns file like handle
        :return: 
        """
        raise NotImplementedError('Not implemented - base class')

    def text(self):
        """
        Returns text output
        :return: 
        """
        return self.read()

    def to_state(self):
        """
        Returns state dictionary for serialization
        :return: 
        """
        js = collections.OrderedDict()
        js['data_read'] = self.data_read
        return js

    def tell(self):
        """
        Current position
        :return: 
        """
        return self.data_read


class FileInputObject(InputObject):
    """
    File input object - reading from the file
    """
    def __init__(self, fname, rec=None, *args, **kwargs):
        super(FileInputObject, self).__init__(*args, **kwargs)
        self.fname = fname
        self.rec = rec
        self.fh = None

    def __enter__(self):
        super(FileInputObject, self).__enter__()
        self.fh = open(self.fname, 'r')

    def __exit__(self, exc_type, exc_val, exc_tb):
        super(FileInputObject, self).__exit__(exc_type, exc_val, exc_tb)
        try:
            self.fh.close()
        except:
            logger.error('Error when closing file %s descriptor' % self.fname)

    def __repr__(self):
        return 'FileInputObject(file=%r)' % self.fname

    def __str__(self):
        return self.fname

    def check(self):
        if not os.path.exists(self.fname):
            raise ValueError('File %s was not found' % self.fname)

    def size(self):
        return os.path.getsize(self.fname)

    def read(self, size=None):
        data = self.fh.read(size)
        self.sha256.update(data)
        self.data_read += len(data)
        return data

    def handle(self):
        return self.fh

    def to_state(self):
        """
        Returns state dictionary for serialization
        :return: 
        """
        js = collections.OrderedDict()
        js['type'] = 'FileInputObject'
        js['fname'] = self.fname
        js['data_read'] = self.data_read
        return js


class LinkInputObject(InputObject):
    """
    Input object using link - remote load
    """
    def __init__(self, url, rec=None, headers=None, auth=None, timeout=None, *args, **kwargs):
        super(LinkInputObject, self).__init__(*args, **kwargs)
        self.url = url
        self.headers = headers
        self.auth = auth
        self.r = None
        self.rec = None
        self.timeout = timeout
        self.kwargs = kwargs

    def __enter__(self):
        super(LinkInputObject, self).__enter__()
        self.r = requests.get(self.url, stream=True, allow_redirects=True, headers=self.headers, auth=self.auth,
                              timeout=self.timeout,
                              **self.kwargs)

    def __exit__(self, exc_type, exc_val, exc_tb):
        super(LinkInputObject, self).__exit__(exc_type, exc_val, exc_tb)
        try:
            self.r.close()
        except:
            logger.error('Error when closing url %s descriptor' % self.url)

    def __repr__(self):
        return 'LinkInputObject(url=%r)' % self.url

    def __str__(self):
        return self.url

    def check(self):
        return True

    def size(self):
        return -1

    def read(self, size=None):
        data = self.r.raw.read(size)
        self.sha256.update(data)
        self.data_read += len(data)
        return data

    def text(self):
        data = self.r.text
        self.sha256.update(data)
        self.data_read += len(data)
        return data

    def handle(self):
        return self.r.raw

    def to_state(self):
        """
        Returns state dictionary for serialization
        :return: 
        """
        js = collections.OrderedDict()
        js['type'] = 'LinkInputObject'
        js['url'] = self.url
        js['data_read'] = self.data_read
        js['headers'] = self.headers
        js['timeout'] = self.timeout
        js['rec'] = self.rec
        return js


class RequestFailedTooManyTimes(Exception):
    """Request just keeps failing"""


class RequestReturnedEmptyResponse(Exception):
    """Internally used exception to signalize need for reconnect"""


class ReconnectingLinkInputObject(InputObject):
    """
    Input object that is able to reconnect to the source in case of the problem.
    Link should support calling HEAD method and RangeBytes.
    If this is not supported no reconnection will be used.
    """
    def __init__(self, url, rec=None, headers=None, auth=None, timeout=None,
                 max_reconnects=None, start_offset=0, pre_data_reconnect_hook=None, *args, **kwargs):
        super(ReconnectingLinkInputObject, self).__init__(*args, **kwargs)
        self.url = url
        self.headers = headers
        self.auth = auth
        self.rec = rec
        self.timeout = timeout
        self.max_reconnects = max_reconnects
        self.start_offset = start_offset
        self.pre_data_reconnect_hook = pre_data_reconnect_hook

        # Overall state
        self.stop_event = threading.Event()
        self.content_length = None
        self.total_reconnections = 0
        self.reconnections = 0
        self.last_reconnection = 0
        self.head_headers = None
        self.range_bytes_supported = False

        # Current state
        self.r = None
        self.current_content_length = 0

        self.kwargs = kwargs

    def _interruptible_sleep(self, sleep_time):
        """
        Sleeps the current thread for given amount of seconds, stop event terminates the sleep - to exit the thread.
        :param sleep_time:
        :return:
        """
        if sleep_time is None:
            return

        sleep_time = float(sleep_time)

        if sleep_time == 0:
            return

        sleep_start = time.time()
        while not self.stop_event.is_set():
            time.sleep(0.1)
            if time.time() - sleep_start >= sleep_time:
                return

    def _sleep_adaptive(self, current_attempt):
        """
        Sleeps amount of time w.r.t, attempt
        :param current_attempt: 
        :return: 
        """
        if current_attempt <= 5:
            self._interruptible_sleep(10)
        elif current_attempt <= 15:
            self._interruptible_sleep(60)
        elif current_attempt <= 25:
            self._interruptible_sleep(5 * 60)
        else:
            self._interruptible_sleep(10 * 60)

    def _load_info(self):
        """
        Performs head request on the url to load info & capabilities
        :return: 
        """
        r = None
        current_attempt = 0

        # First - determine full length & partial request support
        while not self.stop_event.is_set():
            try:
                r = requests.head(self.url, allow_redirects=True, headers=self.headers, auth=self.auth, timeout=self.timeout)
                if r.status_code / 100 != 2:
                    logger.error('Link %s does not support head request or link is broken' % self.url)
                    return
                r.raise_for_status()
                break

            except Exception as e:
                logger.warning('Exception in fetching the url: %s' % e)
                logger.debug(traceback.format_exc())
                current_attempt += 1
                if self.max_reconnects is not None and current_attempt >= self.max_reconnects:
                    raise RequestFailedTooManyTimes()
                self._sleep_adaptive(current_attempt)

        self.head_headers = r.headers

        # Load content length, quite essential
        try:
            self.content_length = int(r.headers['Content-Length'])
        except KeyError:
            logger.error('Link %s does not return content length' % self.url)

        # Determine if range partial request is supported by the server
        if 'Accept-Ranges' in r.headers:
            self.range_bytes_supported = 'bytes' in r.headers['Accept-Ranges']

        logger.debug('URL %s head loaded. Content length: %s, accept range: %s, headers: %s'
                     % (self.url, self.content_length, self.range_bytes_supported, self.head_headers))

    def _get_headers(self):
        """
        Builds headers for the request
        :return: 
        """
        headers = dict(self.headers) if self.headers is not None else {}

        if (self.start_offset is None or self.start_offset == 0) and self.data_read == 0:
            return headers

        headers['Range'] = 'bytes=%s-' % (self.start_offset + self.data_read)
        return headers

    def _is_all_data_loaded(self):
        """
        Returns true if all requested data is loaded already.
        :return: 
        """
        if self.content_length is None:
            logger.warning('Could not determine if finished...')
            return None

        return self.content_length - self.start_offset - self.data_read <= 0

    def _request(self):
        """
        Connects to the server
        :return: 
        """
        headers = self._get_headers()

        # Close previous connection
        try:
            if self.r is not None:
                self.r.close()
        except:
            logger.warning('Error when closing old url %s connection' % self.url)

        # Iterate several times until we get the response
        current_attempt = 0
        while not self.stop_event.is_set():
            try:
                logger.info('Reconnecting[%02d, %02d] to the url: %s, timeout: %s, headers: %s'
                            % (current_attempt, self.reconnections, self.url, self.timeout, headers))
                self.r = requests.get(self.url, stream=True, allow_redirects=True, headers=headers, auth=self.auth,
                                      timeout=self.timeout, **self.kwargs)
                self.r.raise_for_status()
                break

            except Exception as e:
                logger.warning('Exception in fetching the url: %s' % e)
                logger.debug(traceback.format_exc())
                current_attempt += 1
                if self.max_reconnects is not None and current_attempt >= self.max_reconnects:
                    raise RequestFailedTooManyTimes()
                self._sleep_adaptive(current_attempt)

        self.reconnections += 1
        self.last_reconnection = time.time()

        # Load content length
        try:
            self.current_content_length = int(self.r.headers['Content-Length'])
        except KeyError:
            logger.error('Link %s does not return content length' % self.url)

    def __enter__(self):
        super(ReconnectingLinkInputObject, self).__enter__()

        # Load basic info
        self._load_info()

        # Initial request
        self._request()

    def __exit__(self, exc_type, exc_val, exc_tb):
        super(ReconnectingLinkInputObject, self).__exit__(exc_type, exc_val, exc_tb)
        try:
            self.r.close()
        except:
            logger.error('Error when closing url %s descriptor' % self.url)

    def __repr__(self):
        return 'ReconnectingLinkInputObject(url=%r)' % self.url

    def __str__(self):
        return self.url

    def check(self):
        return True

    def size(self):
        return -1

    def read(self, size=None):
        """
        Reading a given size of data from the stream. 
        :param size: 
        :return: 
        """
        while not self.stop_event.is_set():
            try:
                data = self.r.raw.read(size)
                ln = len(data)

                # If we read empty data inspect if it is expected end of stream or not
                if ln == 0:
                    logger.info('Empty data read, total so far: %s, offset: %s, content length: %s'
                                % (self.data_read, self.start_offset, self.content_length))

                    all_data_loaded = self._is_all_data_loaded()

                    # Could not determine if final, end then. End also if read it all
                    if all_data_loaded is None or all_data_loaded is True:
                        return data

                    # Problems -> need to reconnect and try over
                    raise RequestReturnedEmptyResponse()

                # Non-null data, all went right -> pass further
                self.sha256.update(data)
                self.data_read += ln
                return data

            except Exception as e:
                logger.error('Exception when reading data: %s' % e)
                logger.debug(traceback.format_exc())

                # Going to reconnect, ask where we stopped
                if self.pre_data_reconnect_hook is not None:
                    self.pre_data_reconnect_hook(self)
                self._interruptible_sleep(10)
                self._request()
                continue

        # Unreachable
        return None

    def handle(self):
        return self.r.raw

    def to_state(self):
        """
        Returns state dictionary for serialization
        :return: 
        """
        js = collections.OrderedDict()
        js['type'] = 'ReconnectingLinkInputObject'
        js['url'] = self.url
        js['start_offset'] = self.start_offset
        js['data_read'] = self.data_read
        js['headers'] = dict(self.headers) if self.headers is not None else None
        js['timeout'] = self.timeout
        js['rec'] = self.rec

        js['max_reconnects'] = self.max_reconnects
        js['content_length'] = self.content_length
        js['total_reconnections'] = self.total_reconnections
        js['reconnections'] = self.reconnections
        js['last_reconnection'] = self.last_reconnection
        js['head_headers'] = dict(self.head_headers) if self.head_headers is not None else None
        js['range_bytes_supported'] = self.range_bytes_supported
        js['current_content_length'] = self.range_bytes_supported
        return js


