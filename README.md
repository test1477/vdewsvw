Here's the full script modified to fetch SBOM data for a single repository:

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
    return re.sub(r'^[^0-9]*', '', version)

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
        if package['name'] == repo_name or package['name'] == f"com.github.{repo_name}":
            continue

        version_info = clean_version(package.get('versionInfo', ""))
        package_name = package['name'].replace(':', '-')
        bom_ref = f"{package_name}-{version_info}"
        
        if ':' in package['name']:
            pkg_manager, pkg_name = package['name'].split(':', 1)
            if pkg_manager == 'pip':
                pkg_manager = 'pypi'
            purl = f"pkg:{pkg_manager}/{pkg_name}@{version_info}"
        else:
            pkg_manager = ""
            pkg_name = package['name']
            purl = f"pkg:{package['name']}@{version_info}"
        
        if "pkg:actions" in bom_ref.lower() or "actions:" in package['name'].lower():
            continue
        
        if pkg_manager == 'pypi':
            bom_ref = f"pkg:{pkg_manager}-{pkg_name}-{version_info}"
            package_name = f"{pkg_manager}:{pkg_name}"
        
        components.append({
            "bom-ref": f"pkg:{bom_ref}",
            "type": "library",
            "name": package_name,
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

def process_repository(owner, repo_name, access_token, output_base):
    g = Github(access_token)
    
    try:
        repo = g.get_repo(f"{owner}/{repo_name}")
        logging.info(f"Processing repository: {repo.full_name}")
        
        if repo.archived:
            logging.info(f"Skipping archived repository: {repo.full_name}")
            return
        
        repo_version = get_latest_release_version(repo)
        if repo_version:
            dependencies = get_dependencies(owner, repo_name, access_token)
            sbom_data = generate_sbom(dependencies, owner, repo_name, repo_version)
            output_file = os.path.join(output_base, f"{repo_name}.json")
            save_sbom_to_file(sbom_data, output_file)
        else:
            logging.info(f"Skipping {repo_name} as it has no releases")
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred for {repo_name}: {http_err}")
    except Exception as err:
        logging.error(f"An error occurred for {repo_name}: {err}")

if __name__ == "__main__":
    owner = "example-owner"
    repo_name = "example-repo"
    access_token = "your-github-access-token"
    output_base = r"c:\sre\sbom"

    os.makedirs(output_base, exist_ok=True)
    process_repository(owner, repo_name, access_token, output_base)
```

This script fetches SBOM data for a single repository, skipping it if it's archived or has no releases. Replace the placeholder values in the `if __name__ == "__main__":` block with your actual repository details and access token before running the script.

Citations:
[1] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/11902716/dc271a97-b25c-48bc-bf41-1f211b3bdc55/paste.txt
