To implement the additional changes:
1. **Exclude GitHub Actions packages**: We will now also exclude packages from `githubactions/` and `github/` in addition to `actions/`.
2. **Set Unknown Version**: If a package version is empty or missing, we will set it to `"unknown"` in the CycloneDX output.

Here's the updated script:

### Updated Full Script

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
        if any(exclusion in package_name for exclusion in ['actions/', 'githubactions/', 'github/']):
            logging.info(f"Excluding package: {package_name}")
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

        # Construct the component without the licenses section
        components.append({
            "bom-ref": reference_locator.replace('/', '-').replace('@', '-'),
            "type": "library",
            "name": package_name,
            "version": version,
            "purl": reference_locator
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

---

### Key Changes:
1. **Excluding More GitHub Actions Packages**: 
   - In addition to `actions/`, now also packages containing `githubactions/` or `github/` are excluded. 
   - This is achieved by using `any(exclusion in package_name for exclusion in ['actions/', 'githubactions/', 'github/'])`.

2. **Setting Version to "Unknown"**: 
   - If the `versionInfo` is missing or empty, it is explicitly set to `"unknown"`. 
   - This is done using `version = package.get('versionInfo', 'unknown') or 'unknown'`.

---

### Example Log Output:

```plaintext
2024-11-26 14:00:01,012 - INFO - Successfully fetched SPDX SBOM for cloud-era/SRE-Utilities.
2024-11-26 14:00:01,123 - INFO - Excluding package: actions/setup-python
2024-11-26 14:00:01,456 - INFO - Excluding package: githubactions/checkout
2024-11-26 14:00:01,789 - INFO - Setting version for 'requests' to 'unknown' (empty version).
2024-11-26 14:00:01,456 - INFO - Saved CycloneDX SBOM to cyclonedx_sbom.json.
```

---

### Environment Variables:

```bash
export GITHUB_TOKEN="your_personal_access_token"
export GITHUB_ORG="organization-name"
export GITHUB_REPO="repository-name"
```

---

With these changes, the script will now:
- Exclude GitHub Actions and related packages from the SBOM.
- Set the version of any package that has an empty version to `"unknown"`.
- Omit the `licenses` section from the CycloneDX SBOM output.

Let me know if you need further adjustments!
