Below is the full Python script to generate an SBOM in CycloneDX format, leveraging your logic about using the PURL (`referenceLocator`) for constructing fields like `bom-ref` and `name`:

```python
import json
import pytz
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

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
    
    # Metadata for the repository itself
    repo_name = f"{owner}/{repo}"
    metadata_component = {
        "bom-ref": f"pkg:repository/{repo_name}@{repo_version}",
        "type": "application",
        "name": repo_name,
        "version": repo_version,
        "purl": f"pkg:repository/{repo_name}@{repo_version}"
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
            "version": package.get('versionInfo', ''),
            "purl": purl
        })

    # Generate timestamp in ISO format
    eastern = pytz.timezone('US/Eastern')
    timestamp = datetime.now(eastern).isoformat(timespec='seconds')

    # Complete SBOM structure
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


def save_sbom_to_file(sbom_data, output_file):
    """
    Saves the generated SBOM data to a JSON file.

    Args:
        sbom_data (dict): The SBOM data to save.
        output_file (str): Path to the output file.
    """
    try:
        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(sbom_data, file, indent=4)
        logging.info(f"SBOM saved to {output_file}")
    except Exception as e:
        logging.error(f"Failed to save SBOM: {e}")


if __name__ == "__main__":
    # Example input data
    example_dependencies = {
        "sbom": {
            "packages": [
                {
                    "referenceLocator": "pkg:pypi/datadog@0.44.0",
                    "versionInfo": "0.44.0"
                },
                {
                    "referenceLocator": "pkg:npm/react@17.0.2",
                    "versionInfo": "17.0.2"
                },
                {
                    "referenceLocator": "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
                    "versionInfo": "3.12.0"
                }
            ]
        }
    }

    # Set owner, repo, and version
    owner = "example_owner"
    repo = "example_repo"
    repo_version = "1.0.0"

    # Generate the SBOM
    sbom = generate_sbom(example_dependencies, owner, repo, repo_version)

    # Save the SBOM to a file
    output_file = "sbom_example.json"
    save_sbom_to_file(sbom, output_file)
```

### Features of the Script:
1. **Metadata Construction:**
   - Includes repository-level metadata like `bom-ref`, `name`, and `purl`.

2. **Dynamic Component Handling:**
   - Processes the `referenceLocator` to populate `bom-ref`, `name`, and `purl` fields dynamically.
   - Skips packages without a valid `referenceLocator` and logs a warning.

3. **Timestamp Generation:**
   - Adds a timestamp in ISO 8601 format.

4. **File Output:**
   - Saves the SBOM in a human-readable JSON format.

5. **Example Data:**
   - Includes a sample dependency list to test the script.

---

### Example Output (JSON):
For the given example dependencies, the SBOM will look like this:

```json
{
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": "2024-11-26T10:00:00-05:00",
        "component": {
            "bom-ref": "pkg:repository/example_owner/example_repo@1.0.0",
            "type": "application",
            "name": "example_owner/example_repo",
            "version": "1.0.0",
            "purl": "pkg:repository/example_owner/example_repo@1.0.0"
        }
    },
    "components": [
        {
            "bom-ref": "pkg-pypi-datadog-0.44.0",
            "type": "library",
            "name": "pypi:datadog",
            "version": "0.44.0",
            "purl": "pkg:pypi/datadog@0.44.0"
        },
        {
            "bom-ref": "pkg-npm-react-17.0.2",
            "type": "library",
            "name": "npm:react",
            "version": "17.0.2",
            "purl": "pkg:npm/react@17.0.2"
        },
        {
            "bom-ref": "pkg-maven-org.apache.commons-commons-lang3-3.12.0",
            "type": "library",
            "name": "maven:org.apache.commons:commons-lang3",
            "version": "3.12.0",
            "purl": "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
        }
    ]
}
```

Let me know if you have additional requirements!
