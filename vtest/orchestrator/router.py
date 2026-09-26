import os
import json
from dotenv import load_dotenv
from groq import Groq

# Load environment variables from .env file
load_dotenv()

def get_testing_strategy(context: dict) -> dict:
    """
    Passes the codebase context to Groq (Llama 3) to determine 
    which testing agents should be triggered.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable is missing.")

    client = Groq(api_key=api_key)
    
    prompt = f"""
    You are the Orchestrator AI for a local code testing agent.
    Analyze the following codebase context and decide which testing sub-agents to run.
    
    Context:
    - Primary Language: {context.get('primary_language')}
    - Framework: {context.get('framework')}
    - Total Files: {context.get('total_files')}
    
    Rules:
    - 'run_unit': true for almost all codebases with logic.
    - 'run_security': true for all codebases.
    - 'run_stress': true ONLY if the framework typically runs a web server or API (e.g., Next.js, Spring Boot, FastAPI, Node.js). False for simple scripts.
    
    You must respond ONLY with a valid JSON object matching this exact schema:
    {{
        "run_unit": true/false,
        "run_security": true/false,
        "run_stress": true/false,
        "reasoning": "string explaining why"
    }}
    """

    # Call Llama 3 via Groq API
    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0.1
    )
    
    return json.loads(response.choices[0].message.content)

# import os
# import json
# from dotenv import load_dotenv
# from google import genai
# from google.genai import types

# # Load environment variables from .env file
# load_dotenv()

# def get_testing_strategy(context: dict) -> dict:
#     """
#     Passes the codebase context to Gemini 2.0 Flash to determine 
#     which testing agents should be triggered.
#     """
#     api_key = os.environ.get("GEMINI_API_KEY")
#     if not api_key:
#         raise ValueError("GEMINI_API_KEY environment variable is missing.")

#     client = genai.Client(api_key=api_key)
    
#     prompt = f"""
#     You are the Orchestrator AI for a local code testing agent.
#     Analyze the following codebase context and decide which testing sub-agents to run.
    
#     Context:
#     - Primary Language: {context.get('primary_language')}
#     - Framework: {context.get('framework')}
#     - Total Files: {context.get('total_files')}
    
#     Rules:
#     - 'unit': True for almost all codebases with logic.
#     - 'security': True for all codebases.
#     - 'stress': True ONLY if the framework typically runs a web server or API (e.g., Next.js, Spring Boot, FastAPI, Node.js). False for simple scripts or unknown frameworks.
#     """

#     # We force Gemini to reply strictly with a JSON object 
#     # matching this schema so our CLI doesn't break trying to parse it.
#     response = client.models.generate_content(
#         model='gemini-2.0-flash',
#         contents=prompt,
#         config=types.GenerateContentConfig(
#             response_mime_type="application/json",
#             response_schema={"type": "OBJECT", "properties": {
#                 "run_unit": {"type": "BOOLEAN"},
#                 "run_security": {"type": "BOOLEAN"},
#                 "run_stress": {"type": "BOOLEAN"},
#                 "reasoning": {"type": "STRING"}
#             }}
#         ),
#     )
    
#     return json.loads(response.text)