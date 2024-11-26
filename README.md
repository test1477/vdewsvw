Certainly! Below is the complete Python script that generates a Software Bill of Materials (SBOM) for a specified GitHub repository. This version constructs the `bom-ref` and `purl` fields based on package information, ensuring that it retains the original package manager names (e.g., "pip" instead of "pypi").

### Full Script

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
    return re.sub(r'^[^0-9]*', '', version) if version else "unknown"

def infer_package_manager(package_name):
    # Infer package manager based on common prefixes or patterns
    if package_name.startswith('npm/'):
        return 'npm', package_name[4:]
    elif package_name.startswith('maven/'):
        return 'maven', package_name[6:]
    elif package_name.startswith('composer/'):
        return 'composer', package_name[9:]
    elif package_name.startswith('cpan/'):
        return 'cpan', package_name[5:]
    elif ':' in package_name:
        return package_name.split(':', 1)
    else:
        # Default to generic if no specific pattern matches
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
        # Skip main repository, GitHub Actions, and related components
        if (package['name'] == repo_name or 
            package['name'] == f"com.github.{repo_name}" or 
            'actions/' in package['name'].lower() or 
            'github/actions' in package['name'].lower()):
            continue

        # Infer the package manager and name
        pkg_manager, pkg_name = infer_package_manager(package['name'])

        version_info = clean_version(package.get('versionInfo', ""))

        # Construct PURL and bom-ref using the inferred manager and name
        purl = f"pkg:{pkg_manager}/{pkg_name}@{version_info}"
        bom_ref = purl  # Use the same value for bom-ref

        # Construct name with the package manager prefix
        name = f"{pkg_manager}:{pkg_name}"

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
        logging.info(f"Processing repository: {repo.full_name}")
        
        os.makedirs(output_base, exist_ok=True)
        
        repo_version = get_latest_release_version(repo)
        
        if repo_version:
            dependencies = get_dependencies(owner, repo.name, access_token)
            sbom_data = generate_sbom(dependencies, owner, repo.name, repo_version)
            output_file = os.path.join(output_base, f"{repo.name}.json")
            save_sbom_to_file(sbom_data, output_file)
        else:
            logging.info(f"No releases found for {repo.name}, using 'unknown' as version")
            dependencies = get_dependencies(owner, repo.name, access_token)
            sbom_data = generate_sbom(dependencies, owner, repo.name, "unknown")
            output_file = os.path.join(output_base, f"{repo.name}.json")
            save_sbom_to_file(sbom_data, output_file)
    
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred for {repo.name}: {http_err}")
    except Exception as err:
        logging.error(f"An error occurred for {repo.name}: {err}")

if __name__ == "__main__":
    # Replace these values with your actual GitHub repository details and access token
    owner = "Eaton-Vance-Corp"
    repo_name = "your-repo-name"
    access_token = "your-github-access-token"
    output_base = r"c:\sre\sbom"

    process_single_repo(owner, repo_name, access_token, output_base)
```

### Key Features:

1. **Dependency Fetching**: The script fetches dependency information from the GitHub API using the dependency graph endpoint.

2. **Package Manager Inference**: The `infer_package_manager` function determines the appropriate package manager based on known prefixes.

3. **SBOM Generation**: The `generate_sbom` function constructs the SBOM with appropriate fields including `bom-ref` and `purl`.

4. **File Output**: The SBOM is saved to a specified JSON file.

5. **Error Handling**: The script includes error handling to manage issues during API calls or file operations.

### Usage Instructions:

- Replace `"your-repo-name"` with the actual name of the repository you want to process.
- Replace `"your-github-access-token"` with a valid GitHub access token that has permissions to access the repository and its dependency graph.
- Adjust the `output_base` path as needed.

This script should now generate an SBOM that aligns with your requirements and retains the correct naming conventions for package managers.
