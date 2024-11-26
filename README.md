Here’s a complete script that includes fetching SPDX SBOM data, converting it to CycloneDX format, and logging warnings for missing data:

### Full Python Script

```python
import logging
import requests
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def fetch_spdx_sbom(repo_name, token):
    """
    Fetch SPDX SBOM data from GitHub API for a repository.

    Args:
        repo_name (str): The repository name in the format 'owner/repo'.
        token (str): Personal access token for GitHub API authentication.

    Returns:
        dict: SPDX SBOM data or None if an error occurs.
    """
    api_url = f"https://api.github.com/repos/{repo_name}/dependency-graph/sbom"
    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching SPDX SBOM for {repo_name}: {e}")
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
        external_refs = package.get('externalRefs', [])
        reference_locator = next(
            (ref['referenceLocator'] for ref in external_refs if ref['referenceType'] == 'purl'), 
            None
        )

        if not reference_locator:
            logging.warning(f"Skipping package '{package.get('name')}' without a referenceLocator.")
            continue

        components.append({
            "bom-ref": reference_locator.replace('/', '-').replace('@', '-'),
            "type": "library",
            "name": package.get('name', 'unknown-package'),
            "version": package.get('versionInfo', ''),
            "purl": reference_locator,
            "licenses": [{"license": {"id": package.get('licenseDeclared', 'NOASSERTION')}}]
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
    # Replace these variables with your configuration
    GITHUB_TOKEN = "your_personal_access_token"  # Add your GitHub access token here
    REPO_NAME = "owner/repository-name"  # Replace with the repo in the format owner/repo
    OUTPUT_FILE = "cyclonedx_sbom.json"  # Path to save the CycloneDX SBOM

    # Fetch SPDX SBOM from GitHub
    spdx_data = fetch_spdx_sbom(REPO_NAME, GITHUB_TOKEN)
    if spdx_data:
        logging.info("Successfully fetched SPDX SBOM.")
        # Convert SPDX to CycloneDX
        cyclonedx_data = convert_spdx_to_cyclonedx(spdx_data)
        # Save CycloneDX SBOM to a file
        save_cyclonedx_sbom(cyclonedx_data, OUTPUT_FILE)
    else:
        logging.error("Failed to fetch SPDX SBOM.")
```

---

### Script Workflow
1. **Fetch SPDX SBOM**: The `fetch_spdx_sbom` function calls GitHub's Dependency Graph API to retrieve the SPDX SBOM for a repository.
2. **Convert to CycloneDX**: The `convert_spdx_to_cyclonedx` function processes the SPDX data and reformats it into CycloneDX structure.
3. **Save CycloneDX SBOM**: The SBOM is saved to a file in JSON format for further use.

---

### Required Inputs
1. Replace `your_personal_access_token` with your GitHub API token.
2. Replace `owner/repository-name` with the GitHub repository (e.g., `cloud-era/SRE-Utilities`).
3. Ensure the output file path (`cyclonedx_sbom.json`) is valid.

---

### Example Log Output
```plaintext
2024-11-26 14:00:01,012 - INFO - Successfully fetched SPDX SBOM.
2024-11-26 14:00:01,123 - WARNING - Skipping package 'requests' without a referenceLocator.
2024-11-26 14:00:01,456 - INFO - Saved CycloneDX SBOM to cyclonedx_sbom.json.
```

Let me know if further customization is needed!
