import litellm
from .utils.convert_to_openai_messages import convert_to_openai_messages
litellm.suppress_debug_info = True
import time

class AgentLlm:
    
    def __init__(self):
        
        self.model = "gpt-4"
        self.system_message = "Given the context from web search and scrapping of the results, Extract the relevant content that will be useful to answer the question. For API related requests, Give preference to curl or python examples."
        self.temperature = 0
        self.top_p = None
        self.context_window = None
        self.max_tokens = None
        self.api_base = None
        self.api_key = None
        self.api_version = None
        self.max_budget = None
        self.user_request_prompt = "\n{search_context}\n\nRequest: {message}"
        
        # prompt = """You are an expert assistant and tool user. For a given request and list of tools, First come up with a plan to best answer the request using the tools. \n\nFill the appropriate parameters for the tools available. \n                               \nTools: \n                               \n1. Search: \n  - Use this when the question would require google search of real-time information and REST API documentations. \n  - Format: {{"tool_name":"search","query":"search query"}}\n\n2. Code Assistant: \n  - You have access to an expert python programmer, send your request to code and execute the program. \n  - Format: {{"tool_name":"code_assistant","instruction":"coding natural language instruction"}} Wrap your tool call inside json block.\n\n### Guidelines:\n\n1. Use the search tool only when real-time information is required or to fetch API documentation that would help to complete the task.\n2. Do not use the search tool to find best practices or best libraries for the request, the code assistant is expected to be aware of these.\n3. Code assistant is aware of the documentation and usage of popular Python libraries like numpy , scipy , pandas, NLTK , sympy etc. No need to search for these documentations.\n4. Use search tool and code execution to perform one task at a time. do not combine multiple queries or tasks into one call.\n\n\n### Example 1:\n\nRequest : here is my stripe api key "xyzf" create a customer with the name "john" email "john@gmail.com" and send an invoice of $1\n\nThought: This request requires using the Stripe API to create a customer and send an invoice. I will use the search tool to fetch latest documentation for creating a customer and sending a invoice, then use the code execution tool to execute the code.\n\nPlan:\n                                                                                                                                                                                                    \n1. Use the `Search` tool to look up the Stripe API documentation for creating a customer and sending an invoice. This will help ensure that I have the correct endpoints and parameters for these API calls.\n\n   ```json\n   {{\n     "tool_name": "search",\n     "query": "Stripe API create customer documentation"\n   }}\n   ```\n\n2. Use the `Code Assistant` tool to creat the customer:\n   ```json\n   {{\n     "tool_name": "code_assistant",\n     "query": "Create a customer using stripe API using stripe API key - \'xyzf\' , customer name - \'john\', email - \'john@gmail.com\'"\n   }}\n   ```    \n3. Use the `Search` tool to lookup the the Stripe API documentation for sending an invoice\n   ```json\n   {{\n     "tool_name": "search",\n     "query": "Stripe API send invoice documentation"\n   }}\n   ```\n4. Use the `Code Assistant` tool to send invoice:\n ```json\n   {{\n     "tool_name": "code_assistant",\n     "query": "Send an invoice of $1 to the customer created"\n   }}\n   ```\n### Example 2:\n\nRequest : Wrrite a python program to parse email using regex \n\nThought: This request requires writing a Python program to parse an email address using regular expressions. I will use the `Code Assistant` tool to write and execute the Python code.\n\nPlan:\n\n1. Use the `Code Assistant` tool to write a Python program that parses an email address using regular expressions:\n\n```json\n{{\n  "tool_name": "code_assistant",\n  "query": "Write a Python program that uses regex to parse an email address from a given string"\n}}\n```\n\n### Example 3:\n\nRequest: File uploaded to - /home/ubuntu/garage/_tmp/abc.jsonl, perform basic analysis and visualization of the file.\n\nThought: This request requires analyzing and visualizing the data in a JSONL file. I will not use a search tool as the task does not need any external information. I will use the `Code Assistant` tool to read the file, perform basic analysis, and create visualizations.\n\nPlan:\n\n1. Use the `Code Assistant` tool to read the JSONL file, perform basic analysis (such as calculating mean, median, mode, and standard deviation for numerical columns), and create visualizations (such as histograms, box plots, and scatter plots) using a library like Matplotlib or Seaborn:\n\n```json\n{{\n  "tool_name": "code_assistant",\n  "query": "File uploaded to - /home/ubuntu/garage/_tmp/abc.jsonl, perform basic analysis, and visualize the results using Matplotlib or Seaborn"\n}}\n```\n\nRequest: {request}"""
        
        
    def run(self,messages):
    
        messages = messages
        
        params = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        
        if self.api_key:
            params["api_key"] = self.api_key
        if self.api_base:
            params["api_base"] = self.api_base
            params["custom_llm_provider"] = "openai"
        if self.api_version:
            params["api_version"] = self.api_version
        if self.max_tokens is not None:
            params["max_tokens"] = self.max_tokens
        if self.temperature is not None:
            params["temperature"] = self.temperature
        if self.top_p is not None:
            params["top_p"] = self.top_p
            
        if self.max_budget:
            litellm.max_budget = self.max_budget
        
        return self.completion(**params)
            
    def completion(self,**params):
        
        # Run completion
        first_error = None
        try:
            response = litellm.completion(**params)
            return response.choices[0].message.content
        except Exception as e:
            # Store the first error
            first_error = e
            # LiteLLM can fail if there's no API key,
            # even though some models (like local ones) don't require it.

            if "api key" in str(first_error).lower() and "api_key" not in params:
                print(
                    "LiteLLM requires an API key. Please set a dummy API key to prevent this message. (e.g `interpreter --api_key x` or `interpreter.llm.api_key = 'x'`)"
                )

            # So, let's try one more time with a dummy API key:
            params["api_key"] = "x"

            try:
                response = litellm.completion(**params)
                return response.choices[0].message.content
            except:
                # If the second attempt also fails, raise the first error
                raise first_error
        

        
        
        
        
        