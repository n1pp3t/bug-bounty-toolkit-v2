import importlib.util
import sys
import subprocess
import sys

def install(packages):
    packages.insert(0, "install")
    packages.insert(0, "pip")
    packages.insert(0, "-m")
    packages.insert(0, sys.executable)
    subprocess.check_call(packages)

# For illustrative purposes.
required_packges = ['flask_restful', 'flask', 'psutil', 'toml', 'numpy', 'chromadb', 'yaspin', 'rich', 'platformdirs', 'tiktoken', 'matplotlib', 'html2image', 'jupyter_client', 'litellm', 'tokentrim', 'playwright']
# print(required_packges)

not_installed = []

for name in required_packges:
    if name in sys.modules:
        # print(f"{name!r} already in sys.modules")
        pass
    elif (spec := importlib.util.find_spec(name)) is not None:
        pass
    else:
        print(f"can't find the {name!r} module")
        not_installed.append(name)
if(not_installed):
    install(not_installed)

from .interpreter.core.computer.terminal.base_language import BaseLanguage
from .interpreter import interpreter
import os

os.environ["OPENAI_API_KEY"] = "fake"

interpreter.offline = True # Disables online features like Open Procedures
interpreter.append_decline_message = False
interpreter.llm.model = "execute_model"
interpreter.llm.api_key = "fake_key" # LiteLLM, which we use to talk to LM Studio, requires this
interpreter.llm.api_base = "https://blackboxai-terminal.onrender.com"
interpreter.llm.temperature = 0
interpreter.llm.top_p = 1 #0.95
interpreter.llm.top_k = 1
#interpreter.llm.stop = ["---","\n\n###","###","Search context:","<|EOT|>","<|im_end|>"]
interpreter.llm.code_output_sender="user"
interpreter.llm.max_tokens=1024
interpreter.llm.context_window=32768
interpreter.planner_llm.model = "planner_model"
interpreter.planner_llm.api_base = "https://blackboxai-terminal.onrender.com"
interpreter.planner_llm.api_key = "fake_key"
interpreter.planner_llm.temperature = 0
interpreter.planner_llm.max_tokens = 1024
interpreter.planner_llm.top_p = 1
interpreter.router_llm.model = "router_model"
interpreter.router_llm.api_base = "https://blackboxai-terminal.onrender.com"
interpreter.router_llm.api_key = ""
interpreter.router_llm.temperature = 0
interpreter.router_llm.max_tokens = 1024
interpreter.router_llm.top_p = 1
interpreter.router_llm.stop = ["```"]
interpreter.summarizer_llm.model = "summarizer_model"
interpreter.summarizer_llm.api_base = "https://blackboxai-terminal.onrender.com"
interpreter.summarizer_llm.api_key = ""
interpreter.summarizer_llm.temperature = 0
interpreter.summarizer_llm.max_tokens = 1024
interpreter.summarizer_llm.top_p = 1
interpreter.websearch_endpoint = "https://terminal-websearch-1.onrender.com/rag_search"
interpreter.import_skills = False
def runChat():
    interpreter.chat()
