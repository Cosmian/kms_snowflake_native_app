import threading




def process_chunk(chunk: list[str]):
    # check if there is a current batch on the thread local storage
    if 'batch' not in threading.local():
        threading.local().batch = []
    # add the chunk to the current batch
    threading.local().batch.extend(chunk)
    # check if the batch is complete
    if len(threading.local().batch) == 1000:
        # add the batch to the global list
        batches.append(threading.local().batch)
        # clear the batch
        threading.local().batch = []