import requests
from typing import List


def search(websearch_endpoint:str,
           search_queries:List[str],
           user_query:str=None,
           rerank_query:str=None,
           **kwargs) -> dict:
    
    headers = {
        "Content-Type": "application/json",
    }
    params = {
        "search_queries": search_queries,
        "user_query":user_query,
        "rerank_query": rerank_query,
        **{key: value for key, value in kwargs.items() if value is not None},
    }
    response = requests.post(
        websearch_endpoint, headers=headers, json=params
    )
    response.raise_for_status()
    search_results = response.json()
    return search_results
    

    
    