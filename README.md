Certainly! Let's incorporate the provided logic into the script to ensure that the components are correctly populated based on the `referenceLocator`. The following full script includes your suggested method for extracting components from the `dependencies` data:

### Full Script with Component Extraction

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

    # Components section
    components = []
    for package in dependencies.get('sbom', {}).get('packages', []):
        reference_locator = package.get('referenceLocator')
        if not reference_locator:
            logging.warning("Skipping a package without a referenceLocator")
            continue

        # Use the referenceLocator directly as the PURL
        purl = reference_locator
        
        # Construct the bom-ref by replacing '/' and '@' with '-'
        bom_ref = reference_locator.replace('/', '-').replace('@', '-')
        
        # Extract name: Everything between the first '/' and '@'
        name = reference_locator.split('/')[1].split('@')[0].replace('/', ':')

        components.append({
            "bom-ref": bom_ref,
            "type": "library",
            "name": name,
            "version": package.get('versionInfo', 'unknown'),  # Default to 'unknown' if no version info is available
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

### Key Features of This Script:

1. **Dependency Fetching**: It fetches dependency information from the GitHub API using the dependency graph endpoint.

2. **Component Extraction**: The script extracts components from the `dependencies` object based on the `referenceLocator`, constructing `purl`, `bom-ref`, and `name` directly from it.

3. **SBOM Generation**: The `generate_sbom` function constructs the SBOM with appropriate fields including `bom-ref`, `name`, and `purl`.

4. **File Output**: The SBOM is saved to a specified JSON file.

5. **Error Handling**: The script includes error handling to manage issues during API calls or file operations.

### Usage Instructions:

- Replace `"your-repo-name"` with the actual name of your GitHub repository.
- Replace `"your-github-access-token"` with a valid GitHub access token that has permissions to access the repository and its dependency graph.
- Adjust the `output_base` path as needed.

This updated script should now correctly populate the components in the SBOM based on the logic you've provided. If you encounter any further issues or have specific requirements you'd like to implement, feel free to ask!
