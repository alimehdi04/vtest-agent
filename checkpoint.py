import asyncio
from pathlib import Path

# Adjust the import path based on your exact folder structure
from vtest.agents.unit_agent import run

async def execute_checkpoint():
    print("🚀 Starting vtest Checkpoint...")
    
    repo_root = Path(".")
    target_file = repo_root / "math_ops.py"
    
    print(f"📂 Target file: {target_file}")
    print("🧠 Extracting AST and requesting pytest suite from Groq (Llama 3.1)...")
    
    # Execute the unit agent
    result = await run(files=[target_file], repo_root=repo_root)
    
    print("\n" + "="*40)
    print("📊 AGENT RESULT SUMMARY")
    print("="*40)
    print(f"Status : {result.summary}")
    if result.error:
        print(f"Errors : {result.error}")
        
    print("\n🔍 FINDINGS:")
    if not result.findings:
        print("No issues found! All tests passed.")
        
    for finding in result.findings:
        print(f"\n[{finding.severity.value.upper()}] {finding.title}")
        print(f"ID         : {finding.id}")
        print(f"File       : {finding.file_path}")
        print(f"Description: {finding.description}")
        print(f"Fix Hint   : {finding.fix_hint}")
        print("-" * 40)

if __name__ == "__main__":
    asyncio.run(execute_checkpoint())