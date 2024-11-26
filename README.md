Here is an updated version of your script that simplifies the process and focuses on fetching the SBOM for a **single repository**. This will make it easier to troubleshoot and verify the output for a specific repo before expanding to the organization level:

### Updated Script for a Single Repository

```python
import requests
import json
import logging
from datetime import datetime
import pytz
import re
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_dependencies(owner, repo, access_token):
    """
    Fetches the dependencies for a single GitHub repository using the dependency graph API.

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

def clean_version(version):
    """
    Cleans the version string by removing any prefixes like '^', '~', etc.

    Args:
        version (str): The version string to clean.

    Returns:
        str: The cleaned version string.
    """
    return re.sub(r'^[^0-9]*', '', version)

def generate_sbom(dependencies, owner, repo, repo_version="1.0.0"):
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
        "bom-ref": f"pkg:github/{repo_name}",
        "type": "application",
        "name": repo_name,
        "version": repo_version,
        "purl": f"pkg:github/{repo_name}@{repo_version}"
    }
    
    components = []
    for package in dependencies['sbom']['packages']:
        # Skip the main repository component and any variations of it
        if package['name'] == repo_name or package['name'] == f"com.github.{repo_name}":
            continue

        version_info = clean_version(package.get('versionInfo', ""))
        package_name = package['name'].replace(':', '-')  # Replace colon with hyphen
        bom_ref = f"{package_name}-{version_info}"
        
        # Extract package manager and name
        if ':' in package['name']:
            pkg_manager, pkg_name = package['name'].split(':', 1)
            # Change 'pip' to 'pypi'
            if pkg_manager == 'pip':
                pkg_manager = 'pypi'
            purl = f"pkg:{pkg_manager}/{pkg_name}@{version_info}"
        else:
            pkg_manager = ""
            pkg_name = package['name']
            purl = f"pkg:{package['name']}@{version_info}"
        
        # Skip components related to GitHub Actions
        if "pkg:actions" in bom_ref.lower() or "actions:" in package['name'].lower():
            continue
        
        # Update bom_ref and name fields for pypi packages
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

    # Generate timestamp in the specified format
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

if __name__ == "__main__":
    # Replace these with your actual GitHub repository details and access token
    owner = "your-org-or-user"
    repo = "your-repo-name"
    access_token = "your-github-access-token"
    output_file = os.path.join("c:\\sre\\sbom", f"{repo}.json")

    try:
        # Fetch dependencies and generate SBOM
        dependencies = get_dependencies(owner, repo, access_token)
        sbom_data = generate_sbom(dependencies, owner, repo)
        save_sbom_to_file(sbom_data, output_file)
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
    except Exception as err:
        logging.error(f"An error occurred: {err}")
```

### Key Changes
1. **Single Repository Focus**:
   - The script is now designed to work for a single repository by taking `owner` and `repo` as input parameters.

2. **Error Handling**:
   - Improved logging to capture errors at every step.

3. **Simplified Output Path**:
   - The output path uses the repository name dynamically.

4. **SBOM Version Default**:
   - Added a default repository version (`1.0.0`) in case no explicit version is needed.

### Usage
1. Update the following placeholders:
   - `owner`: Your GitHub username or organization.
   - `repo`: The name of the repository.
   - `access_token`: Your GitHub Personal Access Token.

2. Run the script:
   ```bash
   python script_name.py
   ```

3. The generated SBOM file will be saved to:
   ```
   c:\sre\sbom\your-repo-name.json
   ```

Let me know if you face any issues!
