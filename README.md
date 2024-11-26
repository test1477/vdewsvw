To include an **access token** for authentication when fetching dependencies or repository data, you typically use it to call an API and retrieve the required data dynamically. Below is an updated version of the script, demonstrating how you can include an **access token** securely and use it for API requests.

### Updated Script with Access Token
```python
import json
import requests
import pytz
from datetime import datetime
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load the access token securely (e.g., from environment variables)
ACCESS_TOKEN = os.getenv("GITHUB_ACCESS_TOKEN")  # Replace with your token if testing locally
if not ACCESS_TOKEN:
    raise ValueError("Access token is missing. Set the GITHUB_ACCESS_TOKEN environment variable.")

def fetch_dependencies(owner, repo):
    """
    Fetches the dependencies for a given repository using the GitHub API.

    Args:
        owner (str): Owner of the repository.
        repo (str): Name of the repository.

    Returns:
        dict: Dependencies fetched from the GitHub API.
    """
    logging.info(f"Fetching dependencies for {owner}/{repo}")
    url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"

    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        logging.info(f"Dependencies fetched successfully for {owner}/{repo}")
        return response.json()
    else:
        logging.error(f"Failed to fetch dependencies: {response.status_code} {response.text}")
        return {}

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
    # Define the repository details
    owner = "example_owner"
    repo = "example_repo"
    repo_version = "1.0.0"

    # Fetch dependencies from GitHub
    dependencies = fetch_dependencies(owner, repo)

    if dependencies:
        # Generate the SBOM
        sbom = generate_sbom(dependencies, owner, repo, repo_version)

        # Save the SBOM to a file
        output_file = f"{repo}_sbom.json"
        save_sbom_to_file(sbom, output_file)
    else:
        logging.error("No dependencies data fetched. Exiting.")
```

---

### Key Updates
1. **Access Token Integration:**
   - The `ACCESS_TOKEN` is fetched from an environment variable (`GITHUB_ACCESS_TOKEN`).
   - The token is included in the `Authorization` header for API requests.

2. **Fetching Dependencies:**
   - The `fetch_dependencies` function calls the GitHub API to fetch the SBOM for a repository.
   - The API endpoint is `https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom`.

3. **Error Handling:**
   - Handles HTTP errors and logs appropriate messages.

4. **Example Input:**
   - Set the `owner` and `repo` variables for your repository.

5. **Environment Variables:**
   - Store your access token securely as an environment variable. You can set it in your terminal:
     ```bash
     export GITHUB_ACCESS_TOKEN="your_access_token"
     ```

---

### How to Run
1. Ensure you have `requests` and `pytz` installed:
   ```bash
   pip install requests pytz
   ```

2. Set your GitHub access token in the environment:
   ```bash
   export GITHUB_ACCESS_TOKEN="your_access_token"
   ```

3. Run the script:
   ```bash
   python sbom_generator.py
   ```

The script dynamically fetches the dependency graph, constructs the SBOM, and saves it to a file.
