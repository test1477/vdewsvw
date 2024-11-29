Certainly! Here's the full updated script incorporating all the changes we've discussed:

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

    Args:
        owner (str): The owner of the repository.
        repo (str): The name of the repository.
        access_token (str): The GitHub access token.

    Returns:
        dict: The JSON response containing the SBOM data.
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

    Args:
        repo (github.Repository.Repository): The GitHub repository object.

    Returns:
        str: The latest release version or None if no releases found.
    """
    try:
        latest_release = repo.get_latest_release()
        version = latest_release.tag_name
        # Remove 'v' prefix if present
        return version[1:] if version.startswith('v') else version
    except GithubException:
        logging.warning(f"No releases found for {repo.full_name}")
        return None

def clean_version(version):
    """
    Cleans the version string by removing any prefixes and handling version ranges.

    Args:
        version (str): The version string to clean.

    Returns:
        str: The cleaned version string.
    """
    if not version:
        return "unknown"
    # Remove leading non-alphanumeric characters
    version = re.sub(r'^[^a-zA-Z0-9]+', '', version)
    # Replace commas with dots for version ranges
    version = version.replace(',', '.')
    # Replace spaces with underscores
    version = version.replace(' ', '_')
    return version

def generate_sbom(dependencies, owner, repo, repo_version):
    """
    Generates a CycloneDX SBOM from the given dependencies.

    Args:
        dependencies (dict): The JSON response containing the SBOM data.
        owner (str): The owner of the repository.
        repo (str): The name of the repository.
        repo_version (str): The version of the repository.

    Returns:
        dict: The generated SBOM data in CycloneDX format.
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
    for package in dependencies['sbom'].get('packages', []):
        purl = next((ref['referenceLocator'] for ref in package.get('externalRefs', []) 
                     if ref.get('referenceType') == 'purl'), None)
        
        # Skip components that start with pkg:github, pkg:githubactions, or pkg:actions
        if purl and (purl.startswith('pkg:github') or 
                     purl.startswith('pkg:githubactions') or 
                     purl.startswith('pkg:actions')):
            continue
        
        if purl:
            name = package.get('name')
            version = clean_version(package.get('versionInfo'))
            
            # Construct bom-ref and purl with version
            bom_ref = f"{purl}-{version}".replace('/', '-').replace('@', '-')
            purl_with_version = f"{purl}@{version}"
            
            components.append({
                "bom-ref": bom_ref,
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl_with_version
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

    Args:
        sbom_data (dict): The generated SBOM data in CycloneDX format.
        filename (str): The path to the file where the SBOM data will be saved.
    """
    try:
        with open(filename, 'w') as f:
            json.dump(sbom_data, f, indent=2)
        logging.info(f"SBOM exported successfully to {filename}")
    except Exception as e:
        logging.exception(f"Error saving SBOM to {filename}")

def process_single_repository(owner, repo_name, access_token, output_base):
    """
    Processes a single GitHub repository, generating SBOM if it has release tags.

    Args:
        owner (str): The owner of the repository.
        repo_name (str): The name of the repository.
        access_token (str): The GitHub access token.
        output_base (str): The base directory where SBOM file will be saved.
    """
    g = Github(access_token)
    
    try:
        repo = g.get_repo(f"{owner}/{repo_name}")
        logging.info(f"Successfully accessed repository: {repo.full_name}")
        
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

    process_single_repository(owner, repo_name, access_token, output_base)
```

This script includes all the modifications we've discussed:

1. It fetches dependencies for a single GitHub repository.
2. It generates a CycloneDX SBOM with components populated from the packages in the dependency data.
3. It excludes GitHub Actions components (those starting with pkg:github, pkg:githubactions, or pkg:actions).
4. It handles version ranges and special characters in version strings.
5. It includes the version in both the `bom-ref` and `purl` fields for each component.
6. It uses the package name directly from the `name` field.
7. It saves the generated SBOM as a JSON file in the specified output directory.

To use this script:

1. Replace the placeholder values in the `if __name__ == "__main__":` block with your actual GitHub repository details and access token.
2. Ensure you have the required Python libraries installed (`requests`, `PyGithub`, `pytz`).
3. Run the script to generate an SBOM for the specified repository.

This script should now correctly handle various version formats and include them in the `bom-ref` and `purl` fields as requested.
