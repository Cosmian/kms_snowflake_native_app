import pandas as pd
import requests
import math
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from _snowflake import vectorized  
# Configuration 
SESSION_POOL_SIZE = 50 
MAX_BATCH_SIZE = 1000 
URL = "remote_service_endpoints" 
# Network requests should have retries 
retry_strategy = Retry( total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504], allowed_methods=["POST"], raise_on_status=False ) 
adapter = HTTPAdapter(max_retries=retry_strategy) 

session_pool = [requests.Session() for _ in range(SESSION_POOL_SIZE)] 
for session in session_pool: 
    session.mount("https://", adapter) 
# Makes the network call 
def make_request(session, data): 
    payload = {"concurrency_test": int(data)} 
    try: 
        response = session.post(URL, json=payload) 
        response.raise_for_status() 
        return response.text 
    except requests.RequestException as e: 
        return f"Error: {e}" 
        
# Process each chunk 
def process_chunk(chunk, session): 
    return [make_request(session, data) for data in chunk] 
    
# Vectorized python UDF 
@vectorized(input=pd.DataFrame, max_batch_size=MAX_BATCH_SIZE) 
def trigger_remote_api(df): 
    chunk_size = math.ceil(len(data) / SESSION_POOL_SIZE) 
    chunks = [(df[0][i:i + chunk_size], session_pool[i // chunk_size]) for i in range(0, len(df[0]), chunk_size)] 
    results = [] 
    with ThreadPoolExecutor(max_workers=SESSION_POOL_SIZE) as executor: 
        futures = [executor.submit(process_chunk, chunk, session) for chunk, session in chunks] 
        for future in futures: results.extend(future.result()) 
        return pd.Series(results)
