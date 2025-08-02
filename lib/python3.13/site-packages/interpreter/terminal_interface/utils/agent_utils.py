import re
import json
import os


def parse_plan(text):
    plan_text = re.split(r"[pP]lan:",text)[1].strip()
    regex = re.compile("\d+\.\s")
    steps = re.split(regex,plan_text)
    tool_call_regex = r"\`\`\`json(\n|.)*?\`\`\`"
    plan_stack = []
    for step in steps:
        tool_dict = {}
        matches = re.finditer(tool_call_regex,step,re.MULTILINE)
        for match in matches:
            if match is not None and "tool_name" in match.group():
                tool_call = json.loads(match.group().replace("```json","").replace("```","").strip())
                tool_dict["call"] = tool_call
                tool_dict["text"] = re.split(tool_call_regex,step)[0]
                plan_stack.append(tool_dict)
    return plan_stack

def parse_router(text):
    route_value = "code_assistant"
    json_txt = text.split("```")[0]
    try:
        route_dict = json.loads(json_txt.strip())
        if "route_to" in route_dict and "planner" in route_dict["route_to"].lower() and "code_assistant" not in route_dict["route_to"].lower():
            route_value = "planner"
        elif "route_to" in route_dict and "summarizer" in route_dict["route_to"].lower() and "code_assistant" not in route_dict["route_to"].lower():
            route_value = "summarizer"
    except:
        route_to_pattern = r"""['"]route_to['"]\s*:\s*["'](.*)?["']"""
        route_matches = re.findall(re.compile(route_to_pattern),text)
        if len(route_matches)>0:
            route_to = route_matches[0].strip().lower()
            if "code_assistant" not in route_to and "planner" in route_to:
                route_value = "planner"
            elif "code_assistant" not in route_to and "summarizer" in route_to:
                route_value = "summarizer"
    return route_value

def parse_summary(text):
    project_folder_name = "root"
    response = text.strip()
    response = response.split("~~~")[0]
    response = response.strip()
    
    project_pattern = "project root folder:"
    if project_pattern in response.lower():
        other_side = response.lower().split(project_pattern)[1]
        project_folder_name = other_side.split("\n")[0]

    result = []
    current_file = None
    current_code = []
    code_block = False

    for line in response.split("\n"):
        if line.startswith("File: "):
            if current_file and current_code:
                result.append({"file": current_file, "code": "\n".join(current_code)})
            current_file = line.split("`")[1].strip()
            current_code = []
            code_block = False
        elif line.startswith("```"):
            code_block = not code_block
        else:
            current_code.append(line)

    if current_file and current_code:
        result.append({"file": current_file, "code": "\n".join(current_code)})

    return result,project_folder_name

def save_code_to_project(file_code_list, project_name,project_dir=os.getcwd()):
    file_path_dir = None
    project_name = project_name.strip().lower().replace(" ", "-").replace("\\", "")

    for file in file_code_list:
        file_path = f"{project_dir}/{project_name}/{file['file']}"
        file_path_dir = file_path[:file_path.rfind("/")]
        os.makedirs(file_path_dir, exist_ok=True)

        with open(file_path, "w") as f:
            f.write(file["code"])

    return file_path_dir

def save_code_file(code,file_path):
    file_path_dir = file_path[:file_path.rfind("/")]
    os.makedirs(file_path_dir, exist_ok=True)
    with open(file_path, "w") as f:
        f.write(code)
    return file_path

def construct_crag_context(document_context):
    documents = document_context.split("\n\n======== SEARCH RESULTS ========\n")
    context = ""
    for idx,doc in enumerate(documents):
        context+= (f"\n=== DOCUMENT {idx+1} ===\n\n"+doc)
    return context
    
def parse_crag_ranking(text):
    pattern = r"""relevant_documents\s*:\s*\[(.*)\]"""
    matches = re.findall(re.compile(pattern),text)
    rankings = []
    try:
        if len(matches)>0:
            ranking_text = matches[0].strip().lower()
            if len(ranking_text.strip())>0:
                rankings = [int(rank.strip()) for rank in ranking_text.split(",")]
    except Exception as e:
        print(f"Exception during parsing crag ranking",e)
    return rankings

def reconstruct_search_context(document_context,rankings=[]):
    documents = document_context.split("\n\n======== SEARCH RESULTS ========\n")
    # if no ranking take first 3
    rankings = rankings if len(rankings)>0 else list(range(3))
    documents = [documents[rank-1] for rank in rankings]
    context = "\n\n======== SEARCH RESULTS ========\n".join(documents)
    return context

def select_rewrite_query(queries):
    select_queries = [query for query in queries if "python" in query.lower()]
    if len(select_queries)==0:
        select_queries = queries
    return sorted(select_queries,key=lambda q:len(q.split()),reverse=True)[0]   
    
    