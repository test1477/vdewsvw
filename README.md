It seems you're looking for the full script that processes SBOMs while excluding archived repositories. Below is the complete script with the requested modifications:

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
    """
    Fetches the dependencies for a given GitHub repository using the dependency graph API.
    """
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
    """
    Fetches the latest release version for a given GitHub repository.
    """
    try:
        latest_release = repo.get_latest_release()
        version = latest_release.tag_name
        return version[1:] if version.startswith('v') else version
    except GithubException:
        logging.warning(f"No releases found for {repo.full_name}")
        return None

def clean_version(version):
    """
    Cleans the version string by removing any prefixes like '^', '~', etc.
    """
    return re.sub(r'^[^0-9]*', '', version)

def generate_sbom(dependencies, owner, repo, repo_version):
    """
    Generates a CycloneDX SBOM from the given dependencies.
    """
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
        if not version_info:
            version_info = "unknown"

        purl = next((ref['referenceLocator'] for ref in package.get('externalReferences', []) if ref['referenceType'] == 'purl'), None)
        
        if not purl:
            continue

        # Extract package manager and name
        if ':' in package['name']:
            pkg_manager, pkg_name = package['name'].split(':', 1)
            if pkg_manager == 'pip':
                pkg_manager = 'pypi'
            
            # Update bom_ref and name fields for pypi packages
            if pkg_manager == 'pypi':
                bom_ref = f"pkg:{pkg_manager}-{pkg_name}-{version_info}"
                package_name = f"{pkg_manager}:{pkg_name}"
            else:
                bom_ref = f"{package['name']}-{version_info}"
                package_name = package['name']
        else:
            pkg_manager = ""
            pkg_name = package['name']
            bom_ref = f"{package['name']}-{version_info}"
            package_name = package['name']
        
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
    """
    Saves the SBOM data to a JSON file.
    """
    try:
        with open(filename, 'w') as f:
            json.dump(sbom_data, f, indent=2)
        logging.info(f"SBOM exported successfully to {filename}")
    except Exception as e:
        logging.exception(f"Error saving SBOM to {filename}")

def process_organization(org_name, access_token, output_base):
    """
    Processes all non-archived repositories in a GitHub organization, generating SBOMs for those with release tags.
    """
    g = Github(access_token)
    
    try:
        org = g.get_organization(org_name)
        logging.info(f"Successfully accessed organization: {org_name}")
        
        os.makedirs(output_base, exist_ok=True)
        
        for repo in org.get_repos():
            if repo.archived:
                logging.info(f"Skipping archived repository: {repo.full_name}")
                continue

            logging.info(f"Processing repository: {repo.full_name}")
            try:
                repo_version = get_latest_release_version(repo)
                if repo_version:
                    dependencies = get_dependencies(org_name, repo.name, access_token)
                    sbom_data = generate_sbom(dependencies, org_name, repo.name, repo_version)
                    output_file = os.path.join(output_base, f"{repo.name}.json")
                    save_sbom_to_file(sbom_data, output_file)
                else:
                    logging.info(f"Skipping {repo.name} as it has no releases")
            except requests.exceptions.HTTPError as http_err:
                logging.error(f"HTTP error occurred for {repo.name}: {http_err}")
            except Exception as err:
                logging.error(f"An error occurred for {repo.name}: {err}")
    
    except GithubException as e:
        logging.exception(f"Error accessing organization {org_name}")
    except Exception as e:
        logging.exception("Error processing organization")

if __name__ == "__main__":
    # Replace these values with your actual GitHub organization details and access token
    org_name = "Eaton-Vance-Corp"
    access_token = "your-github-access-token"
    output_base = r"c:\sre\sbom"

    process_organization(org_name, access_token, output_base)
```

### Key Features of the Script:

- **Excludes Archived Repositories**: Skips processing of archived repositories.
- **Handles PyPI Packages**: Updates `bom_ref` and `package_name` fields specifically for PyPI packages.
- **Version Handling**: Sets the version to `"unknown"` if it is empty.
- **SBOM Generation**: Generates CycloneDX SBOMs using GitHub's dependency graph API.
- **Logging**: Provides detailed logs for each step of processing.

### Usage Instructions:

1. **Install Required Libraries**:

   Ensure you have the required libraries installed:

   ```sh
   pip install requests PyGithub pytz
   ```

2. **Update Placeholder Values**:

   Replace the placeholder values in the `if __name__ == "__main__":` block with your actual GitHub organization details and access token.

3. **Run the Script**:

   Execute the script to process all non-archived repositories within your specified organization and generate CycloneDX SBOMs.

Citations:
[1] https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/11902716/dc271a97-b25c-48bc-bf41-1f211b3bdc55/paste.txt
