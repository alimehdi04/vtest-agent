import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

def ask(prompt: str, system: str = "", temperature: float = 0.1) -> str:
    """
    Wrapper for the Groq API (Llama 3.1).
    Keeps the agent files clean from LLM boilerplate.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY is not set in the .env file")
        
    client = Groq(api_key=api_key)
    
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    
    response = client.chat.completions.create(
        model="openai/gpt-oss-20b",
        messages=messages,
        temperature=temperature
    )
    
    return response.choices[0].message.content