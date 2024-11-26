Got it! I understand now that you want to exclude GitHub Actions components from the CycloneDX SBOM output based on the package name and the `bom-ref` field. Specifically, you want to check if the package name contains specific terms like `"pkg:actions"`, `"actions:"`, or references to GitHub Actions packages and repositories, and exclude them from the output.

Let's adjust the script to implement this exclusion in the right places. We'll handle both the `bom-ref` field and the `name` field for excluding GitHub Actions components.

### Updated Script:

```python
import os
import logging
import requests
from datetime import datetime

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
        package_name = package.get('name')

        # Exclude GitHub Actions, GitHubActions, and github packages by name
        if any(exclusion in package_name.lower() for exclusion in ['actions/', 'githubactions/', 'github/']):
            logging.info(f"Excluding GitHub Action package: {package_name}")
            continue

        external_refs = package.get('externalRefs', [])
        reference_locator = next(
            (ref['referenceLocator'] for ref in external_refs if ref['referenceType'] == 'purl'), 
            None
        )

        if not reference_locator:
            logging.warning(f"Skipping package '{package_name}' without a referenceLocator.")
            continue

        # Get version or set to "unknown" if version is empty
        version = package.get('versionInfo', 'unknown') or 'unknown'

        # Construct the component, handling the "unknown" version case
        if version == 'unknown':
            bom_ref = f"pkg:{package_name.replace('/', '-')}-unknown"
            purl = f"pkg:{reference_locator}@unknown"
        else:
            bom_ref = reference_locator.replace('/', '-').replace('@', '-')
            purl = reference_locator

        # Skip components related to GitHub Actions based on bom-ref or package name
        if "pkg:actions" in bom_ref.lower() or "actions:" in package['name'].lower():
            logging.info(f"Skipping GitHub Action component: {package_name}")
            continue

        components.append({
            "bom-ref": bom_ref,
            "type": "library",
            "name": package_name,
            "version": version,
            "purl": purl
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
    import json
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

### Key Updates:
1. **Exclusion based on `bom-ref` and `package_name`:** 
   - The script now checks if `"pkg:actions"` exists in the `bom-ref` field or if `"actions:"` is found in the `name` field of the package.
   - If these conditions are met, the package is skipped and will not be added to the `components` list.

   ```python
   if "pkg:actions" in bom_ref.lower() or "actions:" in package['name'].lower():
       logging.info(f"Skipping GitHub Action component: {package_name}")
       continue
   ```

2. **Handling Unknown Version (`version = 'unknown'`):**
   - If the `versionInfo` field is empty or missing, it is set to `"unknown"` as a fallback.
   - The `bom-ref` and `purl` are appropriately formatted to reflect `"unknown"` for these components.

### What this script does:
- **Excludes GitHub Actions components**: Any components whose name contains `"actions/"`, `"githubactions/"`, or `"github/"` (such as workflow actions) will not be included in the CycloneDX SBOM output.
- **Handles unknown versions**: If a package does not have a version, `"unknown"` will be assigned, and the `bom-ref` and `purl` will be formatted to reflect this.
  
### Example Exclusion Logs:
```text
INFO: Skipping GitHub Action component: githubactions/Eaton-Vance-Corp/configure-aws-credentials
INFO: Skipping GitHub Action component: githubactions/jfrog/setup-jfrog-cli
```

Now, the script should correctly exclude GitHub Actions-related components and handle unknown versions. Let me know if the exclusions are now working as expected!
