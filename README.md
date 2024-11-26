Here's the updated script with the owner, repository names, and `GITHUB_ACCESS_TOKEN` hardcoded. This simplifies the script by removing dynamic CLI arguments and environment variable handling.

### Updated Script

```python
import requests
import json
import os
import logging
from github import Github
from github import GithubException
from datetime import datetime
import pytz
import re

# Hardcoded configurations
OWNER = "YourOwnerName"
REPOS = ["repo1", "repo2", "repo3"]  # List of repositories
ACCESS_TOKEN = "your_github_access_token"  # Hardcoded GitHub Access Token
OUTPUT_BASE = "c:\\sre\\sbom"  # Output directory for SBOMs

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_dependencies(owner, repo, access_token):
    logging.info(f"Fetching dependencies for repo: {owner}/{repo}")
    url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"
    headers = {
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github+json"
    }
    response = requests.get(url, headers=headers)
    logging.info(f"GitHub API response status: {response.status_code}")
    response.raise_for_status()
    logging.info("Successfully fetched dependencies.")
    return response.json()

def get_latest_release_version(repo):
    try:
        latest_release = repo.get_latest_release()
        version = latest_release.tag_name
        return version[1:] if version.startswith('v') else version
    except GithubException:
        logging.warning(f"No releases found for {repo.full_name}")
        return None

def clean_version(version):
    return re.sub(r'^[^0-9]*', '', version) if version else "unknown"

def infer_package_manager(package_name):
    package_mapping = {
        'npm/': 'npm',
        'maven/': 'maven',
        'composer/': 'composer',
        'cpan/': 'cpan',
        'pip/': 'pypi',
        'nuget/': 'nuget',
        'cargo/': 'cargo',
        'golang/': 'golang',
        'gem/': 'gem'
    }
    for prefix, manager in package_mapping.items():
        if package_name.startswith(prefix):
            return manager, package_name[len(prefix):]
    
    if ':' in package_name:
        parts = package_name.split(':', 1)
        return parts[0], parts[1]
    
    return 'generic', package_name

def generate_sbom(dependencies, owner, repo, repo_version):
    logging.info(f"Generating SBOM for {owner}/{repo}")
    
    repo_name = f"{owner}/{repo}"
    metadata_component = {
        "bom-ref": f"pkg:TRAINPACKAGE/{repo_name}",
        "type": "application",
        "name": repo_name,
        "version": repo_version,
        "purl": f"pkg:TRAINPACKAGE/{repo_name}@{repo_version}"
    }
    
    components = []
    for package in dependencies['sbom']['packages']:
        if (package['name'] == repo_name or 
            package['name'] == f"com.github.{repo_name}" or 
            'actions/' in package['name'].lower() or 
            'github/actions' in package['name'].lower()):
            continue

        pkg_manager, pkg_name = infer_package_manager(package['name'])
        version_info = clean_version(package.get('versionInfo', ""))
        purl = f"pkg:{pkg_manager}/{pkg_name}@{version_info}"
        bom_ref = purl

        components.append({
            "bom-ref": bom_ref,
            "type": "library",
            "name": f"{pkg_manager}:{pkg_name}",
            "version": version_info,
            "purl": purl
        })

    eastern = pytz.timezone('US/Eastern')
    timestamp = datetime.now(eastern).isoformat(timespec='seconds')

    sbom_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": metadata_component
        },
        "components": components
    }

    return sbom_data

def save_sbom_to_file(sbom_data, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(sbom_data, f, indent=2)
        logging.info(f"SBOM exported successfully to {filename}")
    except Exception as e:
        logging.exception(f"Error saving SBOM to {filename}")

def process_single_repo(owner, repo_name, access_token, output_base):
    g = Github(access_token)
    
    try:
        repo = g.get_repo(f"{owner}/{repo_name}")
        logging.info(f"Processing repository: {repo.full_name}")
        
        os.makedirs(output_base, exist_ok=True)
        
        repo_version = get_latest_release_version(repo)
        if not repo_version:
            logging.info(f"No releases found for {repo.name}, using 'unknown' as version")
            repo_version = "unknown"

        dependencies = get_dependencies(owner, repo.name, access_token)
        sbom_data = generate_sbom(dependencies, owner, repo.name, repo_version)
        output_file = os.path.join(output_base, f"{repo.name}.json")
        save_sbom_to_file(sbom_data, output_file)
    
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred for {repo.name}: {http_err}")
    except Exception as err:
        logging.error(f"An error occurred for {repo.name}: {err}")

def process_repositories(owner, repo_names, access_token, output_base):
    for repo_name in repo_names:
        try:
            process_single_repo(owner, repo_name, access_token, output_base)
        except Exception as e:
            logging.error(f"Error processing {repo_name}: {e}")

if __name__ == "__main__":
    process_repositories(OWNER, REPOS, ACCESS_TOKEN, OUTPUT_BASE)
```

### Key Changes
1. **Hardcoded Values:**
   - `OWNER`: Set to the GitHub owner name.
   - `REPOS`: List of repository names to process.
   - `ACCESS_TOKEN`: Hardcoded GitHub access token.
   - `OUTPUT_BASE`: Directory where SBOM files will be saved.

2. **Removed CLI Arguments:** Hardcoded values eliminate the need for dynamic inputs.

3. **Simplified Workflow:** The script directly processes the repositories defined in the `REPOS` list.

### Usage
1. Replace the placeholders in `OWNER`, `REPOS`, and `ACCESS_TOKEN` with your actual GitHub owner name, repository names, and access token.
2. Run the script in your Python environment:
   ```bash
   python sbom_generator.py
   ```
