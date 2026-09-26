import os

def generate_reports(context: dict, all_findings: list):
    """
    Synthesizes findings into a human-readable audit report and a machine-readable fix brief.
    """
    os.makedirs("output", exist_ok=True)
    
    audit_path = "output/audit-report.md"
    brief_path = "output/fix-brief.md"
    
    total_issues = len(all_findings)
    
    # 1. Generate audit-report.md (Human-Readable with GFM Collapsible Tags)
    with open(audit_path, "w", encoding="utf-8") as f:
        f.write(f"# 🛡️ vtest Audit Report — `{os.path.basename(context['path'])}`\n\n")
        f.write(f"**Tech Stack:** {context['primary_language']} / {context['framework']}\n")
        f.write(f"**Total Issues:** {total_issues}\n\n")
        f.write("---\n\n## 📊 Findings Summary\n\n")
        f.write("| ID | Severity | Agent | File:Line | Issue |\n")
        f.write("|---|---|---|---|---|\n")
        
        for issue in all_findings:
            f.write(f"| `{issue['id']}` | **{issue['severity']}** | {issue['agent']} | `{issue['file_line']}` | {issue['issue']} |\n")
        
        f.write("\n## 🔍 Detailed Issue Logs\n\n")
        for issue in all_findings:
            f.write(f"### [{issue['severity']}] {issue['id']} — {issue['issue']}\n")
            f.write(f"- **Location:** `{issue['file_line']}`\n")
            f.write(f"- **Agent:** {issue['agent']}\n\n")
            # GFM Collapsible block to preserve vertical space
            f.write("<details>\n")
            f.write("<summary><strong>Show Raw Execution Log</strong></summary>\n\n")
            f.write(f"```text\n{issue['raw_log']}\n```\n")
            f.write("</details>\n\n")
            f.write("---\n\n")

    # 2. Generate fix-brief.md (Machine-Readable for AI Coding Agents)
    with open(brief_path, "w", encoding="utf-8") as f:
        f.write("<vibe_audit>\n")
        f.write("  <system_fingerprint>\n")
        f.write(f"    <language>{context['primary_language']}</language>\n")
        f.write(f"    <framework>{context['framework']}</framework>\n")
        f.write(f"    <files_scanned>{context['total_files']}</files_scanned>\n")
        f.write("  </system_fingerprint>\n\n")
        
        f.write("  <instructions>\n")
        f.write("    You are an autonomous AI coding assistant. Review the following diagnostic findings.\n")
        f.write("    Remediate the issues in the local codebase, prioritizing CRITICAL and HIGH severity.\n")
        f.write("  </instructions>\n\n")
        
        f.write("  <diagnostic_evaluations>\n")
        for issue in all_findings:
            f.write(f"    <finding id=\"{issue['id']}\" severity=\"{issue['severity']}\" agent=\"{issue['agent']}\">\n")
            f.write(f"      <location>{issue['file_line']}</location>\n")
            f.write(f"      <title>{issue['issue']}</title>\n")
            f.write(f"      <execution_trace>\n")
            f.write(f"<![CDATA[\n{issue['raw_log']}\n]]>\n")
            f.write(f"      </execution_trace>\n")
            f.write(f"    </finding>\n")
        f.write("  </diagnostic_evaluations>\n")
        f.write("</vibe_audit>\n")

    return audit_path, brief_path