To meet the new requirements:
1. **Unknown components**: If the version is unknown or empty, the `bom-ref` and `purl` need to be formatted accordingly, with the version marked as `"unknown"`. The component should look like:
   ```json
   {
       "bom-ref": "pkg:pypi-pytz-unknown",
       "type": "library",
       "name": "pytz",
       "version": "unknown",
       "purl": "pkg:pypi/pytz@unknown"
   }
   ```

2. **Exclude GitHub Actions packages**: GitHub Actions packages (with names like `githubactions/` or `github/`) should be excluded completely. The output should not contain these packages at all.

### Updated Script

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

        # Construct the component, handling the "unknown" version case
        if version == 'unknown':
            bom_ref = f"pkg:{package_name.replace('/', '-')}-unknown"
            purl = f"pkg:{reference_locator}@unknown"
        else:
            bom_ref = reference_locator.replace('/', '-').replace('@', '-')
            purl = reference_locator

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

---

### Key Changes:
1. **Excluded GitHub Actions and Related Packages**:
   - Packages with names containing `actions/`, `githubactions/`, or `github/` are excluded completely from the SBOM.
   - This is done with the check: `if any(exclusion in package_name for exclusion in ['actions/', 'githubactions/', 'github/'])`.

2. **Handling Unknown Versions**:
   - If a package has an empty or missing version, the version is set to `"unknown"`.
   - The `bom-ref` and `purl` for these packages are updated to follow this format:
     ```json
     "bom-ref": "pkg:pypi-pytz-unknown",
     "purl": "pkg:pypi/pytz@unknown"
     ```

### Example Output for "Unknown" Version:
```json
{
    "bom-ref": "pkg:pypi-pytz-unknown",
    "type": "library",
    "name": "pytz",
    "version": "unknown",
    "purl": "pkg:pypi/pytz@unknown"
}
```

### Excluded GitHub Actions Package Example:
These packages are excluded from the CycloneDX output:
```json
{
    "bom-ref": "pkg:githubactions-Eaton-Vance-Corp-configure-aws-credentials-1.42A.2A",
    "type": "library",
    "name": "Eaton-Vance-Corp/configure-aws-credentials",
    "version": "1.*.*",
    "purl": "pkg:githubactions/Eaton-Vance-Corp/configure-aws-credentials@1.2A.2A"
}
```

---

### Summary:
- **GitHub Actions packages** (e.g., `githubactions/` and `github/`) are fully excluded.
- **Packages with unknown versions** are marked with `"unknown"` for both version and the associated `bom-ref`/`purl` fields.
  
Let me know if you need more changes!
