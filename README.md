Certainly! I'll modify the script to focus on getting a single repository and adjust the PURL and BOM reference formatting as you've described. Here's the updated script:

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
    return re.sub(r'^[^0-9]*', '', version)

def generate_sbom(dependencies, owner, repo, repo_version):
    logging.info(f"Generating SBOM for {owner}/{repo}")
    
    repo_name = f"{owner}/{repo}"
    
    metadata_component = {
        "bom-ref": f"pkg:github/{repo_name}@{repo_version}",
        "type": "application",
        "name": repo_name,
        "version": repo_version,
        "purl": f"pkg:github/{repo_name}@{repo_version}"
    }
    
    components = []
    for package in dependencies['sbom']['packages']:
        if package['name'] == repo_name or package['name'] == f"com.github.{repo_name}":
            continue

        version_info = clean_version(package.get('versionInfo', ""))
        package_name = package['name'].replace(':', '/')
        
        # Use referenceLocator as PURL
        purl = package.get('externalReferences', [{}])[0].get('referenceLocator', '')
        
        # Generate bom-ref by replacing '/' and '@' with '-'
        bom_ref = purl.replace('/', '-').replace('@', '-')
        
        # Extract name from PURL (between '/' and '@')
        name_match = re.search(r'/([^/@]+)@', purl)
        name = name_match.group(1) if name_match else package_name
        
        if "pkg:actions" in bom_ref.lower() or "actions:" in package['name'].lower():
            continue
        
        components.append({
            "bom-ref": bom_ref,
            "type": "library",
            "name": name,
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
        logging.info(f"Successfully accessed repository: {owner}/{repo_name}")
        
        os.makedirs(output_base, exist_ok=True)
        
        repo_version = get_latest_release_version(repo)
        if repo_version:
            dependencies = get_dependencies(owner, repo_name, access_token)
            sbom_data = generate_sbom(dependencies, owner, repo_name, repo_version)
            output_file = os.path.join(output_base, f"{repo_name}.json")
            save_sbom_to_file(sbom_data, output_file)
        else:
            logging.info(f"Skipping {repo_name} as it has no releases")
    
    except GithubException as e:
        logging.exception(f"Error accessing repository {owner}/{repo_name}")
    except Exception as e:
        logging.exception("Error processing repository")

if __name__ == "__main__":
    # Replace these values with your actual GitHub repository details and access token
    owner = "example-owner"
    repo_name = "example-repo"
    access_token = "your-github-access-token"
    output_base = r"c:\sre\sbom"

    process_single_repo(owner, repo_name, access_token, output_base)
```

Key changes made:

1. Replaced `process_organization` with `process_single_repo` to focus on a single repository.
2. Updated the PURL generation to use the `referenceLocator` from `externalReferences` when available.
3. Modified the `bom-ref` generation to replace '/' and '@' with '-' in the PURL.
4. Updated the component name extraction to get it from between '/' and '@' in the PURL when possible.
5. Adjusted the main script to process a single repository instead of an entire organization.

These changes should address your requirements for processing a single repository and updating the PURL and BOM reference formatting. The script now uses the `referenceLocator` as the PURL when available, and generates the `bom-ref` by replacing '/' and '@' with '-' in the PURL.
