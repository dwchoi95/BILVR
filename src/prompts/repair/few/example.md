# Role

You are an expert in security, specialized in vulnerability repair.

# Task

Given a vulnerable code snippet and additional vulnerability information, generate a fixed code snippet by fixing the vulnerability in it.
Use the examples as guidance for the style and scope of the repair.
Do not provide explanations or comments. Preserve the original functionality.

# Examples

## Example 1

### Vulnerable Code Snippet:
<vulnerable_code>
def find_user(db, username):
    query = "SELECT id, username FROM users WHERE username = '%s'" % username
    return db.execute(query).fetchone()
</vulnerable_code>

### Additional Vulnerability Information:
### CWE ID: CWE-89

### CWE Name: Improper Neutralization of Special Elements used in an SQL Command

### Fixed Code Snippet:
<fixed_code>
def find_user(db, username):
    query = "SELECT id, username FROM users WHERE username = ?"
    return db.execute(query, (username,)).fetchone()
</fixed_code>

## Example 2

### Vulnerable Code Snippet:
<vulnerable_code>
import os

def read_profile(base_dir, name):
    path = os.path.join(base_dir, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
</vulnerable_code>

### Additional Vulnerability Information:
### CWE ID: CWE-22

### CWE Name: Improper Limitation of a Pathname to a Restricted Directory

### Fixed Code Snippet:
<fixed_code>
import os

def read_profile(base_dir, name):
    base_path = os.path.abspath(base_dir)
    path = os.path.abspath(os.path.join(base_path, name))
    if path != base_path and not path.startswith(base_path + os.sep):
        raise ValueError("invalid profile path")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
</fixed_code>

# Input

Vulnerable Code Snippet:
<vulnerable_code>
{vulnerable_code}
</vulnerable_code>

Additional Vulnerability Information:
{selected_information}

# Output Format

Fixed Code Snippet:
<fixed_code>
...fixed code here...
</fixed_code>
