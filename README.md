To modify the script so that it excludes any components related to GitHub Actions and also removes the licenses part from each component, we can make a few adjustments in the `convert_spdx_to_cyclonedx` function. 

### Updated Script

Here’s the revised script with these changes:

```python
import os
import logging
import requests
from datetime import datetime
import json

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def fetch_spdx_sbom(org_name, repo_name, token):
    """
    Fetch SPDX SBOM data from GitHub API for a repository in the organization.

    Args:
        org_name (str): Organization name.
        repo_name (str): Repository name.
        token (str): Personal access token for GitHub API authentication.

    Returns:
        dict: SPDX SBOM data or None if an error occurs.
    """
    api_url = f"https://api.github.com/repos/{org_name}/{repo_name}/dependency-graph/sbom"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching SPDX SBOM for {org_name}/{repo_name}: {e}")
        return None


def convert_spdx_to_cyclonedx(spdx_data):
    """
    Converts SPDX SBOM data to CycloneDX format.

    Args:
        spdx_data (dict): The SPDX document from GitHub's API.

    Returns:
        dict: CycloneDX SBOM format data.
    """
    # Extract metadata
    spdx_doc = spdx_data.get('sbom', {})
    creation_info = spdx_doc.get('creationInfo', {})
    timestamp = creation_info.get('created', datetime.utcnow().isoformat())
    repo_name = spdx_doc.get('name', 'unknown-repo')

    # Define CycloneDX metadata component
    metadata_component = {
        "bom-ref": f"pkg:repository/{repo_name}@main",
        "type": "application",
        "name": repo_name,
        "version": "main",
        "purl": f"pkg:repository/{repo_name}@main"
    }

    # Convert packages
    components = []
    
    for package in spdx_doc.get('packages', []):
        reference_locator = package.get('referenceLocator')
        
        if not reference_locator:
            logging.warning(f"Skipping package '{package.get('name')}' without a referenceLocator.")
            continue

        # Exclude GitHub Actions packages
        if 'actions/' in package.get('name', ''):
            logging.info(f"Skipping GitHub Actions package '{package.get('name')}'.")
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
            "version": package.get('versionInfo', 'unknown')  # Default to 'unknown' if no version info is available
            # Removed licenses part as requested
        })

    # Construct CycloneDX SBOM
    cyclonedx_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": metadata_component
        },
        "components": components
    }

    return cyclonedx_sbom


def save_cyclonedx_sbom(cyclonedx_data, output_file):
    """
    Save CycloneDX SBOM data to a JSON file.

    Args:
        cyclonedx_data (dict): CycloneDX SBOM data.
        output_file (str): File path to save the SBOM.
    """
    try:
        with open(output_file, 'w') as file:
            json.dump(cyclonedx_data, file, indent=2)
        logging.info(f"Saved CycloneDX SBOM to {output_file}")
    except IOError as e:
        logging.error(f"Error saving CycloneDX SBOM: {e}")


if __name__ == "__main__":
    # Replace these variables with your configuration or environment variables
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "your_personal_access_token")  # Add GitHub token here or set as env variable
    ORG_NAME = os.getenv("GITHUB_ORG", "organization-name")  # Replace with the org name
    REPO_NAME = os.getenv("GITHUB_REPO", "repository-name")  # Replace with repo name within org
    OUTPUT_FILE = "cyclonedx_sbom.json"  # Path to save CycloneDX SBOM

    if not GITHUB_TOKEN or not ORG_NAME or not REPO_NAME:
        logging.error("Missing required inputs: GITHUB_TOKEN, GITHUB_ORG, or GITHUB_REPO.")
        exit(1)

    # Fetch SPDX SBOM from GitHub
    spdx_data = fetch_spdx_sbom(ORG_NAME, REPO_NAME, GITHUB_TOKEN)
    
    if spdx_data:
        logging.info(f"Successfully fetched SPDX SBOM for {ORG_NAME}/{REPO_NAME}.")
        
        # Convert SPDX to CycloneDX
        cyclonedx_data = convert_spdx_to_cyclonedx(spdx_data)
        
        # Save CycloneDX SBOM to a file
        save_cyclonedx_sbom(cyclonedx_data, OUTPUT_FILE)
        
    else:
        logging.error(f"Failed to fetch SPDX SBOM for {ORG_NAME}/{REPO_NAME}.")
```

### Key Changes Made:

1. **Exclusion of GitHub Actions Packages**: The script now checks if the package name contains `actions/` and skips those packages. This means any components related to GitHub Actions will not be included in the final output.

2. **Removal of Licenses**: The licenses section has been removed from each component in the CycloneDX output.

### Usage Instructions:

- Ensure you have your GitHub token, organization name, and repository name set either directly in the script or as environment variables.
- Run the script in your Python environment.

### Expected Output:

The resulting `cyclonedx_sbom.json` file should now contain only the relevant library components without any GitHub Actions packages and without license information. If you have further requirements or adjustments needed, feel free to ask!
