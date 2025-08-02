import re

FILE_PATH_REGEX = '''<execute>\\n*File:\s*['"](.*)["']\s*:'''

def is_file_present(text):
    file_creation_path = None
    matches = re.findall(FILE_PATH_REGEX,text,re.MULTILINE)
    if len(matches)>0:
        file_creation_path = matches[0]
    return file_creation_path


def run_text_llm(llm, params):
    ## Setup

    try:
        # Add the system message
        params["messages"][0][
            "content"
        ] #+= "\nTo execute code on the user's machine, write a markdown code block. Specify the language after the ```. You will receive the output. Use any programming language."
    except:
        print('params["messages"][0]', params["messages"][0])
        raise

    ## Convert output to LMC format

    inside_code_block = False
    accumulated_block = ""
    full_message = ""
    language = None
    file_creation_path = None

    for chunk in llm.completions(**params):
        if llm.interpreter.verbose:
            print("Chunk in coding_llm", chunk)

        if "choices" not in chunk or len(chunk["choices"]) == 0:
            # This happens sometimes
            continue

        content = chunk["choices"][0]["delta"].get("content", "")

        if content == None:
            continue

        accumulated_block += content
        full_message += content
        file_creation_path = is_file_present(full_message)
        
        

        if accumulated_block.endswith("`") and (not accumulated_block.endswith("```")):
            # We might be writing "```" one token at a time.
            continue

        # Did we just enter a code block?
        if "```" in accumulated_block and not inside_code_block:
            inside_code_block = True
            accumulated_block = accumulated_block.split("```")[1]

        # Did we just exit a code block?
        if inside_code_block and "```" in accumulated_block:
            
            # Fix for fireworks ai
            if language and "```" in content:
                content = content.split("```")[0]
                yield {
                    "type": "code",
                    "format": language,
                    "content": content,
                }
                
            return

        # If we're in a code block,
        if inside_code_block:
            # If we don't have a `language`, find it
            if language is None and "\n" in accumulated_block:
                language = accumulated_block.split("\n")[0]

                # Default to python if not specified
                if language == "":
                    if llm.interpreter.os == False:
                        language = "python"
                    elif llm.interpreter.os == False:
                        # OS mode does this frequently. Takes notes with markdown code blocks
                        language = "text"
                else:
                    # Removes hallucinations containing spaces or non letters.
                    language = "".join(char for char in language if char.isalpha())

            
            # If we do have a `language`, send it out
            if language:
                
                # Fix for fireworks ai
                # TODO: Fix it , remove language only on codition. Impacting bash calls.
                content = content.replace(language+"\n", "")
                if content.strip() == "```":
                    content = content.replace("```","")
                elif "```" in content:
                    content = content.split("```")[1]
                    
                yield {
                    "type": "code",
                    "format": language,
                    "content": content,
                    "file_creation_path":file_creation_path,
                }

        # If we're not in a code block, send the output as a message
        if not inside_code_block:
            yield {"type": "message", "content": content}
