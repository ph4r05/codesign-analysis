import traceback
import threading
import time
from queue import Queue, Empty as QEmpty
import logging
import coloredlogs


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class Example(object):
    def __init__(self):
        self.stop_event = threading.Event()
        self.local_data = threading.local()
        self.queue = Queue(50)
        self.workers = []

    def consumer_main(self, idx):
        """
        Worker thread main loop
        :return:
        """
        self.local_data.idx = idx
        logger.info('Worker %02d started' % idx)

        while not self.stop_event.is_set():
            job = None
            try:
                job = self.queue.get(True, timeout=1.0)
            except QEmpty:
                time.sleep(0.1)
                continue

            try:
                # Process job in try-catch so it does not break worker
                logger.info('[%02d] Processing job %s' % (idx, job))
                time.sleep(0.2)

            except Exception as e:
                logger.error('Exception in processing job %s: %s' % (e, job))
                logger.debug(traceback.format_exc())

            finally:
                self.queue.task_done()
        logger.info('Worker %02d terminated' % idx)

    def main(self):
        """
        Producer loop
        :return:
        """

        elements = 300
        chunk_size = 20
        generated_cnt = 0

        # Kick off the workers
        for worker_idx in range(0, 25):
            t = threading.Thread(target=self.consumer_main, args=(worker_idx, ))
            self.workers.append(t)
            t.setDaemon(True)
            t.start()

        # Generate
        logger.info('Loading data...')
        while True:
            # Simulate data load
            current_chunk = range(generated_cnt, generated_cnt + chunk_size)
            logger.info('New data chunk loaded: %d' % generated_cnt)

            # Insert one by one to the queue
            for x in current_chunk:
                self.queue.put((x, ))
                generated_cnt += 1

            # Simulate no more data left
            if generated_cnt >= elements:
                break

        logger.info('All jobs are in')

        # Wait on all jobs being finished
        self.queue.join()

        # All data processed, terminate bored workers
        self.stop_event.set()

        # Make sure it is over by joining threads
        for th in self.workers:
            th.join()

        logger.info('Fun is over')


# Launcher
if __name__ == "__main__":
    ex = Example()
    ex.main()




